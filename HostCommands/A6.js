var BufferHelper = require("@shenyan1206/buffer-helper");
var CryptoHelper = require("@shenyan1206/crypto-helper");
var DUKPT = require("@shenyan1206/dukpt");

var LMKManager = require("../LMKManager");
var ErrorCode = require("../ErrorCode");
var KeyType = require("../KeyType");

const RESPOSNE_CODE = "A7";  //Import a Key


//constructor
function A6(){
	console.log("A6 command started");
};

//class functions
A6.prototype.processCommand = function(req) 
{
	
	this._parseRequest(req);
	this._process();
	return this._formatOutput();
};

A6.prototype._parseRequest = function(req)
{
	//data starts after command code
	
	//default value
	this.error = ErrorCode.SUCCESS;
	
	//extract data
	this.key_type = BufferHelper.extract(req, 3).toString();
	this.zmk = BufferHelper.extract(req, 33).toString();
	this.key_zmk = BufferHelper.extract(req, 33).toString();
	this.key_scheme = BufferHelper.extract(req, 1).toString();

	if(this.key_type == KeyType.ZMK) this.error = ErrorCode.INVALID_KEY_TYPE;

	//Don't support Atalla Variant

	//read LMK ID if exist, but don't support multiple LMK now.
	if(String.fromCharCode(req[0]) == "%"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.LMK_id = BufferHelper.extract(req, 2).toString(); 
	}


	console.log(this);
}


A6.prototype._process = function()
{

	if(this.error != ErrorCode.SUCCESS) return; //error in previsou steps, stop processing..

	var zmk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.zmk.substr(1), "hex"), KeyType.ZMK); //get clear ZMK
	var key_clear = CryptoHelper.tdes_dec_ecb(zmk_clear, Buffer.from(this.key_zmk.substr(1), "hex")); //decrypt key.zmk with zmk
	var key_lmk = LMKManager.encryptUnderLMK(key_clear, this.key_type); //encrypt the key under LMK
	kcv = CryptoHelper.kcv(key_clear);

	this.output = (this.key_scheme 
			+ key_lmk.toString("hex")
			+ kcv.toString("hex")
			).toUpperCase();

}


A6.prototype._formatOutput = function()
{
	if(this.error != ErrorCode.SUCCESS) return Buffer.from(RESPOSNE_CODE+this.error);
	else return Buffer.from(RESPOSNE_CODE+this.error+this.output);

}



module.exports = A6;
