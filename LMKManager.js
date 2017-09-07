var CryptoHelper = require("@shenyan1206/crypto-helper");
var fs = require('fs');
var _lmk = []; //list of lmk blocks, each block is hex string

const LMK_FILE = 'lmk.txt';
const LMK_MAX_BLOCKS = 40;



//private functions
function _generateLMKFile() {
	for (var i = 0; i < LMK_MAX_BLOCKS; i++) {
		var buf = CryptoHelper.generateKeyOfSize(8);
		fs.appendFileSync(LMK_FILE, buf.toString("hex")+"\r");
	}
};


//constructor
function LMKManager(){
	_lmk = [];
	//generate lmk if not exisit
	if(! fs.existsSync(LMK_FILE)) _generateLMKFile();

	//load lmk
	_lmk = fs.readFileSync(LMK_FILE).toString().split('\r', LMK_MAX_BLOCKS);

	console.log("LMK file is load, length:" + _lmk.length);
};



//class functions
LMKManager.prototype.encryptUnderLMK = function(clear_key, key_type) 
{
	var lmk_pair = getLMK(key_type); //double length LMK
	
	//clear key is of double length 
	//apply variant to second block of LMK for left part of clear_key
	var lmk_pair_for_left = Buffer.from(lmk_pair);
	lmk_pair_for_left[8] = lmk_pair_for_left[8] ^ 0xA6;
	var left = CryptoHelper.tdes_enc_ecb(lmk_pair_for_left, clear_key.slice(0, 8));



	//apply variant to second block of LMK for left part of clear_key
	var lmk_pair_for_right = Buffer.from(lmk_pair);
	lmk_pair_for_right[8] = lmk_pair_for_right[8] ^ 0x5A;
	var right = CryptoHelper.tdes_enc_ecb(lmk_pair_for_right, clear_key.slice(8, 16));
	
	return Buffer.concat([left, right]);
}

//class functions
LMKManager.prototype.decryptUnderLMK = function(key_lmk, key_type) 
{
	var lmk_pair = getLMK(key_type); //double length LMK
	
	//clear key is of double length 
	//apply variant to second block of LMK for left part of key_lmk
	var lmk_pair_for_left = Buffer.from(lmk_pair);
	lmk_pair_for_left[8] = lmk_pair_for_left[8] ^ 0xA6;
	var left = CryptoHelper.tdes_dec_ecb(lmk_pair_for_left, key_lmk.slice(0, 8));



	//apply variant to second block of LMK for left part of key_lmk
	var lmk_pair_for_right = Buffer.from(lmk_pair);
	lmk_pair_for_right[8] = lmk_pair_for_right[8] ^ 0x5A;
	var right = CryptoHelper.tdes_dec_ecb(lmk_pair_for_right, key_lmk.slice(8, 16));
	
	return Buffer.concat([left, right]);
}

//private functions
function getLMK(key_type)
{
	var variant = getVariantValue(key_type.substr(0, 1));
	var key_pair_index = getLMKPairIndexFromCode(key_type.substr(1));

	//console.log("variant: 0x"+variant.toString(16).toUpperCase()+" key_pair_index:"+key_pair_index);
	
	if(key_pair_index)
	{

		var lmk_pair = Buffer.from(_lmk[key_pair_index]+_lmk[key_pair_index+1], "hex");
		lmk_pair[0] = lmk_pair[0] ^ variant;

		return lmk_pair;
	}

	return null;

	//
}


function getLMKPairIndexFromCode(code)
{
	//LMK at that index and next index will form the key paire
	var CodeToKeyPairList = 
	{
		"00": 4,
		"01": 6,
		"02": 14,
		"03": 16,
		"04": 18,
		"05": 20,
		"06": 22,
		"07": 24,
		"08": 26,
		"09": 28,
		"0A": 30,
		"0B": 32,
		"0C": 34,
		"0D": 36,
		"0E": 38
	};

	return CodeToKeyPairList[code];
}

function getVariantValue(variant)
{
	var variantValues = [
		0x00, 0xA6, 0x5A, 0x6A, 0xDE, 0x2B, 0x50, 0x74, 0x9C, 0xFA
	];

	return variantValues[variant];

}


/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
LMKManager.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
LMKManager.getInstance = function(){
    if(this.instance === null){
        this.instance = new LMKManager();
    }
    return this.instance;
}
 
module.exports = LMKManager.getInstance();
