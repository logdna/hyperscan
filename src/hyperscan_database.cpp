#include <stdio.h>

#include "hyperscan_database.h"

struct PatternOptions
{
    PatternOptions() : startOfMatch(0), singleMatch(0)
    {
    }

    PatternOptions(bool startOfMatch, bool singleMatch) : PatternOptions()
    {
        if(startOfMatch == true)
        {
            this->startOfMatch = HS_FLAG_SOM_LEFTMOST;
        }

        if(singleMatch == true) {
            this->singleMatch = HS_FLAG_SINGLEMATCH;
        }
    }

    unsigned int startOfMatch;
    unsigned int singleMatch;
};

Nan::Persistent<v8::FunctionTemplate> HyperscanDatabase::constructor;

HyperscanDatabase::HyperscanDatabase(std::vector<std::string> patterns) : m_patterns(patterns), m_database(nullptr), m_scratch(nullptr), m_scanMatches()
{
}

HyperscanDatabase::~HyperscanDatabase()
{
}

int HyperscanDatabase::ScanEventHandler(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context)
{
    (static_cast<HyperscanDatabase*>(context))->m_scanMatches.push_back(std::make_tuple(id, from, to));
    return 0;
}

NAN_MODULE_INIT(HyperscanDatabase::Init)
{
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(HyperscanDatabase::New);
    constructor.Reset(ctor);
    ctor->InstanceTemplate()->SetInternalFieldCount(1);
    ctor->SetClassName(Nan::New("HyperscanDatabase").ToLocalChecked());

    Nan::SetPrototypeMethod(ctor, "scan", Scan);

    target->Set(Nan::New("HyperscanDatabase").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(HyperscanDatabase::New)
{
    // Veryify types
    if(!info.IsConstructCall())
    {
        return Nan::ThrowError(Nan::New("HyperscanDatabase::New - called without new keyword").ToLocalChecked());
    }

    if(info.Length() != 2)
    {
        return Nan::ThrowError(Nan::New("HyperscanDatabase::New - unexpected or missing arguments").ToLocalChecked());
    }

    if(!info[0]->IsArray())
    {
        return Nan::ThrowError(Nan::New("HyperscanDatabase::New - first argument is not an array").ToLocalChecked());
    }

    if(!info[1]->IsArray())
    {
        return Nan::ThrowError(Nan::New("HyperscanDatabase::New - second argument is not an array").ToLocalChecked());
    }

    // Convert node array of node strings into a vector of strings
    v8::Local<v8::Array> nodePatterns = v8::Local<v8::Array>::Cast(info[0]);
    std::vector<std::string> patterns;
    patterns.reserve(nodePatterns->Length());
    for(size_t i = 0; i < nodePatterns->Length(); ++i)
    {
        if(!nodePatterns->Get(i)->IsString())
        {
            return Nan::ThrowTypeError("HyperscanDatabase::New - array contains non-string object");
        }

        Nan::Utf8String nodePattern(nodePatterns->Get(i));
        patterns.push_back(std::string(*nodePattern));
    }

    // Convert node array of options into a vector of options
    v8::Local<v8::Array> nodeOptions = v8::Local<v8::Array>::Cast(info[1]);
    std::vector<PatternOptions> options = std::vector<PatternOptions>(nodeOptions->Length());
    for(size_t i = 0; i < nodeOptions->Length(); ++i)
    {
        if(!nodeOptions->Get(i)->IsObject())
        {
            return Nan::ThrowTypeError("HyperscanDatabase::New - array contains non-object object");
        }

        v8::Local<v8::Object> option = nodeOptions->Get(i)->ToObject();

        bool startOfMatch = false;
        v8::Local<v8::String> startOfMatchKey = Nan::New("HS_FLAG_SOM_LEFTMOST").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), startOfMatchKey).FromJust())
        {
            v8::Local<v8::Value> startOfMatchValue = option->Get(startOfMatchKey);
            if (startOfMatchValue->IsBoolean())
            {
                startOfMatch = startOfMatchValue->BooleanValue();
            }
        }

        bool singleMatch = false;
        v8::Local<v8::String> singleMatchKey = Nan::New("HS_FLAG_SINGLEMATCH").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), singleMatchKey).FromJust())
        {
            v8::Local<v8::Value> singleMatchValue = option->Get(singleMatchKey);
            if (singleMatchValue->IsBoolean())
            {
                singleMatch = singleMatchValue->BooleanValue();
            }
        }

        options.push_back(PatternOptions(startOfMatch, singleMatch));
    }

    // If some options are missing we fill them in
    for (size_t i = options.size(); i < patterns.size(); ++i)
    {
        options.push_back(PatternOptions());
    }

    // Create object and bind it to node object
    HyperscanDatabase *obj = new HyperscanDatabase(patterns);
    obj->Wrap(info.Holder());

    // Convert patterns from a vector of strings to a const char * const *
    std::vector<const char*> cStrings;
    cStrings.reserve(patterns.size());
    std::vector<unsigned int> ids;
    ids.reserve(patterns.size());
    std::vector<unsigned int> flags;
    flags.reserve(patterns.size());
    for(size_t i = 0; i < patterns.size(); ++i) {
        cStrings.push_back(patterns[i].c_str());
        ids.push_back(i);
        PatternOptions option = options[i];
        flags.push_back((option.startOfMatch & HS_FLAG_SOM_LEFTMOST) | (option.singleMatch & HS_FLAG_SINGLEMATCH));
    }

    // Compile the patterns into a database
    hs_compile_error_t *compileError;
    if(hs_compile_multi(cStrings.data(), flags.data(), ids.data(), cStrings.size(), HS_MODE_BLOCK, NULL, &obj->m_database, &compileError) != HS_SUCCESS)
    {
        hs_free_compile_error(compileError);
        return Nan::ThrowTypeError(std::string("HyperscanDatabase::New - failed to compile pattern database: ").append(std::string(compileError->message)).c_str());
    }

    // Create scratch space that hyperscan uses while scanning
    if(hs_alloc_scratch(obj->m_database, &obj->m_scratch) != HS_SUCCESS)
    {
        hs_free_database(obj->m_database);
        return Nan::ThrowTypeError("HyperscanDatabase::New - failed to allocate scratch space for hyperscan");
    }

    // Return newly created object
    info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(HyperscanDatabase::Scan)
{
    // Get the object that is having scan invoked on
    HyperscanDatabase *self = Nan::ObjectWrap::Unwrap<HyperscanDatabase>(info.This());

    // Check input types
    if(info.Length() != 1)
    {
        return Nan::ThrowTypeError("HyperscanDatabase::Scan - unexpected number of arguments");
    }

    if(!info[0]->IsString())
    {
        return Nan::ThrowTypeError("HyperscanDatabase::Scan - expected string as first argument");
    }

    // Convert input from a node string to a c++ string
    Nan::Utf8String nodeInput(info[0]);
    std::string input(*nodeInput);

    // Do the search with hyperscan
    if(hs_scan(self->m_database, input.c_str(), input.length(), 0, self->m_scratch, HyperscanDatabase::ScanEventHandler, static_cast<void*>(self)) != HS_SUCCESS)
    {
        hs_free_scratch(self->m_scratch);
        hs_free_database(self->m_database);
        return Nan::ThrowTypeError("HyperscanDatabase::Scan - hyperscan failed to scan input string");
    }

    // Transform our vector of tuples into an array of objects for scan matches
    v8::Local<v8::Array> nodeMatches = v8::Array::New(info.GetIsolate());
    unsigned int matchCount = 0;
    for(const auto& match : self->m_scanMatches)
    {
        v8::Local<v8::Object> nodeMatch = v8::Object::New(info.GetIsolate());
        nodeMatch->Set(Nan::New("patternId").ToLocalChecked(), Nan::New(static_cast<uint32_t>(std::get<0>(match))));
        nodeMatch->Set(Nan::New("offsetStart").ToLocalChecked(), Nan::New(static_cast<uint32_t>(std::get<1>(match))));
        nodeMatch->Set(Nan::New("offsetEnd").ToLocalChecked(), Nan::New(static_cast<uint32_t>(std::get<2>(match))));
        nodeMatches->Set(matchCount++, nodeMatch);
    }

    info.GetReturnValue().Set(nodeMatches);
}
