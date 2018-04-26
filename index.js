const addon = require('./build/Release/hyperscan');

module.exports.HyperscanDatabase = addon.HyperscanDatabase;

let db = new addon.HyperscanDatabase(['test.*stuff'], [{
    HS_FLAG_SOM_LEFTMOST: true
    , singleMatch: true
}]);

console.log(db.scan('some stuff over here test anything goes here and stuf'));
