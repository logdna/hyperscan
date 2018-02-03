#include <stdio.h>

#include "hyperscan_database.h"

Nan::Persistent<v8::FunctionTemplate> HyperscanDatabase::constructor;

HyperscanDatabase::HyperscanDatabase( std::vector<std::string> patterns ) : m_patterns( patterns ), m_database( nullptr ), m_scratch( nullptr ), m_scanMatches()
{
}

HyperscanDatabase::~HyperscanDatabase()
{
}

int HyperscanDatabase::ScanEventHandler( unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context )
{
    ( static_cast<HyperscanDatabase*>( context ) )->m_scanMatches.push_back( std::make_tuple( id, from, to ) );
    return 0;
}

NAN_MODULE_INIT( HyperscanDatabase::Init )
{
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>( HyperscanDatabase::New );
    constructor.Reset( ctor );
    ctor->InstanceTemplate()->SetInternalFieldCount( 1 );
    ctor->SetClassName( Nan::New( "HyperscanDatabase" ).ToLocalChecked() );

    Nan::SetPrototypeMethod( ctor, "scan", Scan );

    target->Set( Nan::New( "HyperscanDatabase" ).ToLocalChecked(), ctor->GetFunction() );
}

NAN_METHOD( HyperscanDatabase::New )
{
    // Veryify types
    if( !info.IsConstructCall() )
    {
        return Nan::ThrowError( Nan::New( "HyperscanDatabase::New - called without new keyword" ).ToLocalChecked() );
    }

    if( info.Length() != 1 )
    {
        return Nan::ThrowError( Nan::New( "HyperscanDatabase::New - unexpected or missing arguments" ).ToLocalChecked() );
    }

    if( !info[0]->IsArray() )
    {
        return Nan::ThrowError( Nan::New( "HyperscanDatabase::New - argument type is not an array" ).ToLocalChecked() );
    }

    // Convert node array of node strings into a vector of strings
    v8::Local<v8::Array> nodePatterns = v8::Local<v8::Array>::Cast( info[0] );
    std::vector<std::string> patterns = std::vector<std::string>();
    for( unsigned int i = 0; i < nodePatterns->Length(); ++i )
    {
        if( !nodePatterns->Get(i)->IsString() )
        {
            return Nan::ThrowTypeError( "HyperscanDatabase::New - array contains non-string object" );
        }

        Nan::Utf8String nodePattern( nodePatterns->Get( i ) );
        patterns.push_back( std::string( *nodePattern ) );
    }

    // Create object and bind it to node object
    HyperscanDatabase *obj = new HyperscanDatabase( patterns );
    obj->Wrap( info.Holder() );

    // Convert patterns from a vector of strings to a const char * const *
    std::vector<const char*> cStrings;
    std::vector<unsigned int> ids;
    std::vector<unsigned int> flags;
    unsigned int idCount = 0;
    for( const auto& pattern : obj->m_patterns )
    {
        cStrings.push_back( pattern.c_str() );
        ids.push_back( idCount++ );
        flags.push_back( HS_FLAG_DOTALL | HS_FLAG_SOM_LEFTMOST );
    }

    // Compile the patterns into a database
    hs_compile_error_t *compileError;
    if( hs_compile_multi( cStrings.data(), flags.data(), ids.data(), cStrings.size(), HS_MODE_BLOCK, NULL, &obj->m_database, &compileError ) != HS_SUCCESS )
    {
        hs_free_compile_error( compileError );
        return Nan::ThrowTypeError( std::string( "HyperscanDatabase::New - failed to compile pattern database: " ).append( std::string( compileError->message ) ).c_str() );
    }

    // Create scratch space that hyperscan uses while scanning
    if( hs_alloc_scratch( obj->m_database, &obj->m_scratch ) != HS_SUCCESS )
    {
        hs_free_database( obj->m_database );
        return Nan::ThrowTypeError( "HyperscanDatabase::New - failed to allocate scratch space for hyperscan" );
    }

    // Return newly created object
    info.GetReturnValue().Set( info.Holder() );
}

NAN_METHOD( HyperscanDatabase::Scan )
{
    // Get the object that is having scan invoked on
    HyperscanDatabase *self = Nan::ObjectWrap::Unwrap<HyperscanDatabase>( info.This() );

    // Check input types
    if( info.Length() != 1 )
    {
        return Nan::ThrowTypeError( "HyperscanDatabase::Scan - unexpected number of arguments" );
    }

    if( !info[0]->IsString() )
    {
        return Nan::ThrowTypeError( "HyperscanDatabase::Scan - expected string as first argument" );
    }

    // Convert input from a node string to a c++ string
    Nan::Utf8String nodeInput( info[0] );
    std::string input( *nodeInput );

    // Do the search with hyperscan
    if( hs_scan( self->m_database, input.c_str(), input.length(), 0, self->m_scratch, HyperscanDatabase::ScanEventHandler, static_cast<void*>( self ) ) != HS_SUCCESS )
    {
        hs_free_scratch( self->m_scratch );
        hs_free_database( self->m_database );
        return Nan::ThrowTypeError( "HyperscanDatabase::Scan - hyperscan failed to scan input string" );
    }

    // Transform our vector of tuples into an array of objects for scan matches
    v8::Local<v8::Array> nodeMatches = v8::Array::New( info.GetIsolate() );
    unsigned int matchCount = 0;
    for( const auto& match : self->m_scanMatches )
    {
        v8::Local<v8::Object> nodeMatch = v8::Object::New( info.GetIsolate() );
        nodeMatch->Set( Nan::New( "patternId" ).ToLocalChecked(), Nan::New( static_cast<uint32_t>( std::get<0>( match ) ) ) );
        nodeMatch->Set( Nan::New( "offsetStart" ).ToLocalChecked(), Nan::New( static_cast<uint32_t>( std::get<1>( match ) ) ) );
        nodeMatch->Set( Nan::New( "offsetEnd" ).ToLocalChecked(), Nan::New( static_cast<uint32_t>( std::get<2>( match ) ) ) );
        nodeMatches->Set( matchCount++, nodeMatch );
    }

    info.GetReturnValue().Set( nodeMatches );
}
