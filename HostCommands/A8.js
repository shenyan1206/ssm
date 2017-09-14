var BufferHelper = require("@shenyan1206/buffer-helper");
var CryptoHelper = require("@shenyan1206/crypto-helper");
var DUKPT = require("@shenyan1206/dukpt");

var LMKManager = require("../LMKManager");
var ErrorCode = require("../ErrorCode");
var KeyType = require("../KeyType");

const RESPOSNE_CODE = "A9";  //Export a Key


//constructor
function A8(){
	console.log("A8 command started");
};

//class functions
A8.prototype.processCommand = function(req) 
{
	
	this._parseRequest(req);
	this._process();
	return this._formatOutput();
};

A8.prototype._parseRequest = function(req)
{
	//data starts after command code
	
	//default value
	this.error = ErrorCode.SUCCESS;
	this.ZMK_TMK_flag = "0"; //default ZMK


	//extract data
	this.key_type = BufferHelper.extract(req, 3).toString();
	
	if(String.fromCharCode(req[0]) == ";"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.ZMK_TMK_flag = this.key_type = BufferHelper.extract(req, 1).toString();
	}
	this.ZMK_TMK = BufferHelper.extract(req, 33).toString(); //1A+32H
	this.key_lmk = BufferHelper.extract(req, 33).toString();
	this.key_scheme = BufferHelper.extract(req, 1).toString();

	//Don't support Atalla Variant

	//read LMK ID if exist, but don't support multiple LMK now.
	if(String.fromCharCode(req[0]) == "%"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.LMK_id = BufferHelper.extract(req, 2).toString(); 
	}

	if(this.ZMK_TMK_flag == "0")
		this.zmk_tmk_key_type = KeyType.ZMK; //ZMK
	else
		this.zmk_tmk_key_type = KeyType.TMK; //TMK

	console.log(this);
}


A8.prototype._process = function()
{

	if(this.error != ErrorCode.SUCCESS) return; //error in previsou steps, stop processing..

	var key_clear = LMKManager.decryptUnderLMK(Buffer.from(this.key_lmk.substr(1), "hex"), this.key_type); //get clear key
	var zmk_tmk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.ZMK_TMK.substr(1), "hex"), this.zmk_tmk_key_type); //get clear ZMK/TMK
	var key_zmk = CryptoHelper.tdes_enc_ecb(zmk_tmk_clear, key_clear);

	kcv = CryptoHelper.kcv(key_clear);

	this.output = (this.key_scheme 
			+ key_zmk.toString("hex")
			+ kcv.toString("hex")
			).toUpperCase();

}


A8.prototype._formatOutput = function()
{
	if(this.error != ErrorCode.SUCCESS) return Buffer.from(RESPOSNE_CODE+this.error);
	else return Buffer.from(RESPOSNE_CODE+this.error+this.output);

}



module.exports = A8;
