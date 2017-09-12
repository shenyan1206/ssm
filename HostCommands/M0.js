var BufferHelper = require("@shenyan1206/buffer-helper");
var CryptoHelper = require("@shenyan1206/crypto-helper");
var DUKPT = require("@shenyan1206/dukpt");

var LMKManager = require("../LMKManager");
var ErrorCode = require("../ErrorCode");
var KeyType = require("../KeyType");

const RESPOSNE_CODE = "M1";


//constructor
function M0(){
	console.log("M0 command started");
};

//class functions
M0.prototype.processCommand = function(req) 
{
	
	this._parseRequest(req);
	this._process();
	return this._formatOutput();
};

M0.prototype._parseRequest = function(req)
{
	//data starts after command code
	
	//default value
	this.error = ErrorCode.SUCCESS;

	//extract data
	this.mode = BufferHelper.extract(req, 2).toString(); //2N
	this.input_format_flag = BufferHelper.extract(req, 1).toString(); //1N
	this.output_format_flag = BufferHelper.extract(req, 1).toString(); //1N
	this.key_type = BufferHelper.extract(req, 3).toString(); //3H
	this.key = BufferHelper.extract(req, 33).toString(); //1A+32H
	
	if(this.key_type == KeyType.BDK_TYPE_1 ||
		this.key_type == KeyType.BDK_TYPE_2 ||
		this.key_type == KeyType.BDK_TYPE_3){

		this.ksn_descriptor = BufferHelper.extract(req, 3).toString(); //3H

		//ksn_descriptor consist 3 digits, each represents: BDK_ID length, subkey length, device id length.
		//expect "609"
		if(this.ksn_descriptor != "609") this.error = ErrorCode.INVALID_KSN_DESCRIPTOR;

		this.ksn = BufferHelper.extract(req, 20).toString(); //20H
	}
	if(this.mode == "01" || this.mode == "02" || this.mode == "03")
	{
		this.iv = Buffer.from(BufferHelper.extract(req, 16).toString(), "hex"); //extract 16 bytes, conver to hex string, then to Buffer
	}

	//uint16
	this.message_length = Buffer.from(BufferHelper.extract(req, 4).toString(), "hex").readUInt16BE(); //read 4H convert to 2byte uint16

	//encrypted_message: buffer type
	if(this.input_format_flag == "0") //binary
		this.decrypted_message = BufferHelper.extract(req, this.message_length);
	else if(this.input_format_flag == "1") //hex string
		this.decrypted_message = Buffer.from(BufferHelper.extract(req, this.message_length).toString(), "hex"); //read N hex covert to Buffer
	else this.error = ErrorCode.INVALID_INPUT_FORMAT_FLAG; 
	


	//read LMK ID if exist, but don't support multiple LMK now.
	if(String.fromCharCode(req[0]) == "%"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.LMK_id = BufferHelper.extract(req, 2).toString(); 
	}


	console.log(this);
}


M0.prototype._process = function()
{

	if(this.error != ErrorCode.SUCCESS) return; //error in previous steps, stop processing..
	
	//only support DUKPT for now
	if(this.key_type != KeyType.BDK_TYPE_1 &&
		this.key_type != KeyType.BDK_TYPE_2 &&
		this.key_type != KeyType.BDK_TYPE_3){

		this.error = ErrorCode.INVALID_KEY_TYPE; 
		return;
	}

	var bdk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.key.substr(1),"hex"), this.key_type); //remove U in front, then decrypt

	var dukpt_key = DUKPT.GetKey(bdk_clear, Buffer.from(this.ksn, "hex"), DUKPT.KEY_TYPE_DATA);


	output_iv = "";
	if(this.mode == "00"){ //ECB
		this.encrypted_message = CryptoHelper.tdes_enc_ecb(dukpt_key, this.decrypted_message);
	}
	else{ //CBC
		this.encrypted_message = CryptoHelper.tdes_enc_cbc(dukpt_key, this.decrypted_message, this.iv);
		output_iv = Buffer.alloc(8).toString("hex"); //all zero
	}
	
	this.encrypted_message_length = Buffer.alloc(2);
	this.encrypted_message_length.writeUInt16BE(this.encrypted_message.length); //4H, or 2 Byte, buffer

	this.output = output_iv + //output iv, all 0
					this.encrypted_message_length.toString("hex") +
					this.encrypted_message.toString("hex");

	this.output = this.output.toUpperCase();
}


M0.prototype._formatOutput = function()
{
	if(this.error != ErrorCode.SUCCESS) return Buffer.from(RESPOSNE_CODE+this.error);
	else return Buffer.from(RESPOSNE_CODE+this.error+this.output);

}





module.exports = M0;
