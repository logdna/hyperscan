#include <stdio.h>
#include <node_buffer.h>

#include "hyperscan_database.h"

struct PatternOptions
{
    PatternOptions() : caseLess(0), dotAll(0), multiLine(0), singleMatch(0), allowEmpty(0), utf8(0), ucp(0), preFilter(0), startOfMatch(0)
    {
    }

    PatternOptions(bool caseLess, bool dotAll, bool multiLine, bool singleMatch, bool allowEmpty, bool utf8, bool ucp, bool preFilter, bool startOfMatch) : PatternOptions()
    {
        if(caseLess == true) {
            this->caseLess = HS_FLAG_CASELESS;
        }

        if(dotAll == true) {
            this->dotAll = HS_FLAG_DOTALL;
        }

        if(multiLine == true) {
            this->multiLine =  HS_FLAG_MULTILINE;
        }

        if(singleMatch == true) {
            this->singleMatch = HS_FLAG_SINGLEMATCH;
        }

        if(allowEmpty == true) {
            this->allowEmpty = HS_FLAG_ALLOWEMPTY;
        }

        if(utf8 == true) {
            this->utf8 = HS_FLAG_UTF8;
        }

        if(ucp == true) {
            this->ucp = HS_FLAG_UCP;
        }

        if(preFilter == true) {
            this->preFilter = HS_FLAG_PREFILTER;
        }

        if(startOfMatch == true)
        {
            this->startOfMatch = HS_FLAG_SOM_LEFTMOST;
        }
    }

    unsigned int caseLess;
    unsigned int dotAll;
    unsigned int multiLine;
    unsigned int singleMatch;
    unsigned int allowEmpty;
    unsigned int utf8;
    unsigned int ucp;
    unsigned int preFilter;
    unsigned int startOfMatch;
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
        patterns.push_back(std::string(*nodePattern, nodePattern.length()));
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

        bool caseLess = false;
        v8::Local<v8::String> caseLessKey = Nan::New("HS_FLAG_CASELESS").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), caseLessKey).FromMaybe(false))
        {
            v8::Local<v8::Value> caseLessValue = option->Get(caseLessKey);
            if (caseLessValue->IsBoolean())
            {
                caseLess = caseLessValue->BooleanValue();
            }
        }

        bool dotAll = false;
        v8::Local<v8::String> dotAllKey = Nan::New("HS_FLAG_DOTALL").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), dotAllKey).FromMaybe(false))
        {
            v8::Local<v8::Value> dotAllValue = option->Get(dotAllKey);
            if (dotAllValue->IsBoolean())
            {
                dotAll = dotAllValue->BooleanValue();
            }
        }

        bool multiLine = false;
        v8::Local<v8::String> multiLineKey = Nan::New("HS_FLAG_MULTILINE").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), multiLineKey).FromMaybe(false))
        {
            v8::Local<v8::Value> multiLineValue = option->Get(multiLineKey);
            if (multiLineValue->IsBoolean())
            {
                multiLine = multiLineValue->BooleanValue();
            }
        }

        bool singleMatch = false;
        v8::Local<v8::String> singleMatchKey = Nan::New("HS_FLAG_SINGLEMATCH").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), singleMatchKey).FromMaybe(false))
        {
            v8::Local<v8::Value> singleMatchValue = option->Get(singleMatchKey);
            if (singleMatchValue->IsBoolean())
            {
                singleMatch = singleMatchValue->BooleanValue();
            }
        }

        bool allowEmpty = false;
        v8::Local<v8::String> allowEmptyKey = Nan::New("HS_FLAG_ALLOWEMPTY").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), allowEmptyKey).FromMaybe(false))
        {
            v8::Local<v8::Value> allowEmptyValue = option->Get(allowEmptyKey);
            if (allowEmptyValue->IsBoolean())
            {
                allowEmpty = allowEmptyValue->BooleanValue();
            }
        }

        bool utf8 = false;
        v8::Local<v8::String> utf8Key = Nan::New("HS_FLAG_UTF8").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), utf8Key).FromMaybe(false))
        {
            v8::Local<v8::Value> utf8Value = option->Get(utf8Key);
            if (utf8Value->IsBoolean())
            {
                utf8 = utf8Value->BooleanValue();
            }
        }

        bool ucp = false;
        v8::Local<v8::String> ucpKey = Nan::New("HS_FLAG_UCP").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), ucpKey).FromMaybe(false))
        {
            v8::Local<v8::Value> ucpValue = option->Get(ucpKey);
            if (ucpValue->IsBoolean())
            {
                ucp = ucpValue->BooleanValue();
            }
        }

        bool preFilter = false;
        v8::Local<v8::String> preFilterKey = Nan::New("HS_FLAG_PREFILTER").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), preFilterKey).FromMaybe(false))
        {
            v8::Local<v8::Value> preFilterValue = option->Get(preFilterKey);
            if (preFilterValue->IsBoolean())
            {
                preFilter = preFilterValue->BooleanValue();
            }
        }

        bool startOfMatch = false;
        v8::Local<v8::String> startOfMatchKey = Nan::New("HS_FLAG_SOM_LEFTMOST").ToLocalChecked();
        if(option->HasOwnProperty(Nan::GetCurrentContext(), startOfMatchKey).FromMaybe(false))
        {
            v8::Local<v8::Value> startOfMatchValue = option->Get(startOfMatchKey);
            if (startOfMatchValue->IsBoolean())
            {
                startOfMatch = startOfMatchValue->BooleanValue();
            }
        }

        options.push_back(PatternOptions(caseLess, dotAll, multiLine, singleMatch, allowEmpty, utf8, ucp, preFilter, startOfMatch));
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

    const char* rawInput;
    size_t rawInputLength;
    if (info[0]->IsString())
    {
        Nan::Utf8String nodeInput(info[0]);
        rawInputLength = nodeInput.length();
        rawInput = std::string(*nodeInput, rawInputLength).c_str();
    }
    else if (info[0]->IsUint8Array())
    {
        v8::Local<v8::Object> bufferObj = info[0]->ToObject();
        rawInput = node::Buffer::Data(bufferObj);
        rawInputLength = node::Buffer::Length(bufferObj);
    }
    else
    {
        return Nan::ThrowTypeError("HyperscanDatabase::Scan - expected string or buffer as first argument");
    }

    // Do the search with hyperscan
    if(hs_scan(self->m_database, rawInput, rawInputLength, 0, self->m_scratch, HyperscanDatabase::ScanEventHandler, static_cast<void*>(self)) != HS_SUCCESS)
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

    self->m_scanMatches.clear();
    info.GetReturnValue().Set(nodeMatches);
}
