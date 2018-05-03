const addon = require('./build/Release/hyperscan');

module.exports.HyperscanDatabase = addon.HyperscanDatabase;

let db = new addon.HyperscanDatabase(['test.*stuff'], [{
    HS_FLAG_SOM_LEFTMOST: true
    , singleMatch: true
}]);

let string = 'some stuff over here test anything goes here and  stuff...........................................................................................................................................................................................................................................................................................................................................some stuff over here test anything goes here and  stuff.some stuff over here test anything goes here and  stuff.';
let buffer = Buffer.from(string);
let ret;

for (let i = 0; i < 1000000; ++i) {
    ret = db.scan(buffer, {
        optimizedReturn: 2
    });
}

console.log(ret);
