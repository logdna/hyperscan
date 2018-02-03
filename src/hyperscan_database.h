#ifndef HYPERSCAN_DATABASE_H
#define HYPERSCAN_DATABASE_H

#include <hs.h>
#include <nan.h>
#include <vector>

class HyperscanDatabase : public Nan::ObjectWrap
{
public:
    HyperscanDatabase( std::vector<std::string> patterns );
    ~HyperscanDatabase();

    static int ScanEventHandler( unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context );

    std::vector<std::string> m_patterns;
    hs_database_t *m_database;
    hs_scratch_t *m_scratch;
    std::vector<std::tuple<unsigned int, unsigned long long, unsigned long long>> m_scanMatches;

    static NAN_MODULE_INIT(Init);

    static NAN_METHOD(New);
    static NAN_METHOD(Scan);

    static Nan::Persistent<v8::FunctionTemplate> constructor;
};

#endif
