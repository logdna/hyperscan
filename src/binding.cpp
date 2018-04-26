#include <nan.h>

#include "hyperscan_database.h"

NAN_MODULE_INIT(InitModule)
{
    HyperscanDatabase::Init(target);
}

NODE_MODULE(node_hyperscan, InitModule);
