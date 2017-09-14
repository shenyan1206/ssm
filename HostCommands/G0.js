var BufferHelper = require("@shenyan1206/buffer-helper");
var CryptoHelper = require("@shenyan1206/crypto-helper");
var DUKPT = require("@shenyan1206/dukpt");

var LMKManager = require("../LMKManager");
var ErrorCode = require("../ErrorCode");
var KeyType = require("../KeyType");

const RESPOSNE_CODE = "G1"; //Translate a PIN from BDK to ZPK Encryption


//constructor
function G0(){
	console.log("G0 command started");
};

//class functions
G0.prototype.processCommand = function(req) 
{
	
	this._parseRequest(req);
	this._process();
	return this._formatOutput();
};

G0.prototype._parseRequest = function(req)
{
	//data starts after command code
	
	//default value
	this.error = ErrorCode.SUCCESS;
	this.bdk_key_type = KeyType.BDK_TYPE_1;


	//extract data
	if(String.fromCharCode(req[0]) == "~"){
		this.BDK_flag = BufferHelper.extract(req, 1); 
		this.bdk_key_type = KeyType.BDK_TYPE_2;
	}

	this.bdk = BufferHelper.extract(req, 33).toString(); //1A+32H
	this.zpk = BufferHelper.extract(req, 33).toString(); //1A+32H

	this.ksn_descriptor = BufferHelper.extract(req, 3).toString(); //3H
	//ksn_descriptor consist 3 digits, each represents: BDK_ID length, subkey length, device id length.
	//expect "609"
	if(this.ksn_descriptor != "609") this.error = ErrorCode.INVALID_KSN_DESCRIPTOR;

	this.ksn = BufferHelper.extract(req, 20).toString(); //20H
	this.source_pin_block = BufferHelper.extract(req, 16).toString(); //16H
	this.source_pin_block_format = BufferHelper.extract(req, 2).toString(); //2N
	this.destination_pin_block_format = BufferHelper.extract(req, 2).toString(); //2N
	this.account_number = BufferHelper.extract(req, 12).toString(); //12N

	//read LMK ID if exist, but don't support multiple LMK now.
	if(String.fromCharCode(req[0]) == "%"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.LMK_id = BufferHelper.extract(req, 2).toString(); 
	}

	if(this.source_pin_block_format != "01") this.error = ErrorCode.INVALID_SOURCE_PIN_FORMAT;
	if(this.destination_pin_block_format != "01") this.error = ErrorCode.INVALID_DEST_PIN_FORMAT;


	console.log(this);
}


G0.prototype._process = function()
{

	if(this.error != ErrorCode.SUCCESS) return; //error in previous steps, stop processing..
	var bdk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.bdk.substr(1), "hex"), this.bdk_key_type); //get clear bdk key
	var zpk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.zpk.substr(1), "hex"), KeyType.ZPK); //get clear zpk key

	var derived_key = DUKPT.GetKey(bdk_clear, Buffer.from(this.ksn, "hex"), DUKPT.KEY_TYPE_PIN); //derive key from DUKPT BDK
	var pin_block_clear = CryptoHelper.tdes_dec_ecb(derived_key, Buffer.from(this.source_pin_block, "hex")); //decrypt with BDK's derived key
	var pin_block_zpk = CryptoHelper.tdes_enc_ecb(zpk_clear, pin_block_clear); //encrypt with ZPK clear

	var pin_length = getPinLength(pin_block_clear, this.account_number);

	this.output = (pin_length 
			+ pin_block_zpk.toString("hex")
			+ this.destination_pin_block_format
			).toUpperCase();

}


G0.prototype._formatOutput = function()
{
	if(this.error != ErrorCode.SUCCESS) return Buffer.from(RESPOSNE_CODE+this.error);
	else return Buffer.from(RESPOSNE_CODE+this.error+this.output);

}


function getPinLength(pin_block_clear, account_number)
{
	var acct = Buffer.from("0000"+account_number, "hex"); //16H to 8 bytes buffer
	var c = BufferHelper.XOR(acct, pin_block_clear, true).toString("hex");

	return c.substr(0, 2); //first two digits.

}




module.exports = G0;
