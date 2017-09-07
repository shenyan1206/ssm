var BufferHelper = require("@shenyan1206/buffer-helper");
var CryptoHelper = require("@shenyan1206/crypto-helper");
var DUKPT = require("@shenyan1206/dukpt");

var LMKManager = require("../LMKManager");
var ErrorCode = require("../ErrorCode");
var KeyType = require("../KeyType");

const RESPOSNE_CODE = "A1";


//constructor
function A0(){
	console.log("A0 command started");
};

//class functions
A0.prototype.processCommand = function(req) 
{
	
	this._parseRequest(req);
	this._process();
	return this._formatOutput();
};

A0.prototype._parseRequest = function(req)
{
	//data starts after command code
	
	//default value
	this.error = ErrorCode.SUCCESS;
	this.ZMK_TMK_flag = "0";

	//extract data
	this.mode = BufferHelper.extract(req, 1).toString();
	this.mode_bin = Buffer.from("0"+this.mode, "hex");
	this.key_type = BufferHelper.extract(req, 3).toString();
	this.key_scheme = BufferHelper.extract(req, 1).toString();

	if((this.mode_bin[0] & 0x0A) == 0x0A) //dervie key
	{
		this.derive_key_mode = BufferHelper.extract(req, 1).toString();
		if(this.derive_key_mode == "0")
		{
			this.dukpt_master_key_type = BufferHelper.extract(req, 1).toString();
			this.dukpt_maskter_key = BufferHelper.extract(req, 33).toString(); //1A+32H
			this.ksn = BufferHelper.extract(req, 15).toString();
		

			if(this.dukpt_master_key_type == "1")
			{
				this.bdk_key_type = KeyType.BDK_TYPE_1;
			}
			else if(this.dukpt_master_key_type == "2")
			{
				this.bdk_key_type = KeyType.BDK_TYPE_2;
			}
		}
	}
	if((this.mode_bin[0] & 0x01) == 0x01) //generate and export under ZMK or TMK
	{
		if(String.fromCharCode(req[0]) == ";"){
			BufferHelper.extract(req, 1); //remove delimiter	
			this.ZMK_TMK_flag = BufferHelper.extract(req, 1).toString(); 
		} 

		this.ZMK_TMK = BufferHelper.extract(req, 33).toString(); //1A+32H
		this.key_scheme_zmk_tmk = BufferHelper.extract(req, 1).toString();


		if(this.ZMK_TMK_flag == "0")
		{
			this.zmk_tmk_key_type = KeyType.ZMK; //ZMK
		}
		else
			this.zmk_tmk_key_type = KeyType.TMK; //TMK

	}

	//Don't support Atalla Variant

	//read LMK ID if exist, but don't support multiple LMK now.
	if(String.fromCharCode(req[0]) == "%"){
		BufferHelper.extract(req, 1); //remove delimiter	
		this.LMK_id = BufferHelper.extract(req, 2).toString(); 
	}


	console.log(this);
}

A0.prototype._formatOutput = function()
{
	if(this.error != ErrorCode.SUCCESS) return Buffer.from(RESPOSNE_CODE+this.error);
	else return Buffer.from(RESPOSNE_CODE+this.error+this.output);

}


A0.prototype._process = function()
{

	var key_clear, key_lmk, kcv;

	//generate or derive
	if((this.mode_bin[0] & 0x0A) == 0x0A) //derive key
	{	
		var bdk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.dukpt_maskter_key.substr(1),"hex"), this.bdk_key_type); //remove U in front, then decrypt

		//derive IPEK, then encrypt under LMK
		key_clear = DUKPT.GetIPEK(bdk_clear, Buffer.from(this.ksn+"00000", "hex")); //KSN received is 15H only (no counter), padding counter at end to 20H
		key_lmk = LMKManager.encryptUnderLMK(key_clear, this.key_type);
		kcv = CryptoHelper.kcv(key_clear);
	}
	else //generate key
	{
		if(this.key_scheme != "U") { this.error = ErrorCode.INVALID_KEY_SCHEME; return; }
		key_clear = CryptoHelper.generateKeyOfSize(16);
		key_lmk = LMKManager.encryptUnderLMK(key_clear, this.key_type);
		kcv = CryptoHelper.kcv(key_clear);
	}

	//export or no export
	if((this.mode_bin[0] & 0x01) == 0x01) //export
	{	
		var zmk_tmk_clear = LMKManager.decryptUnderLMK(Buffer.from(this.ZMK_TMK.substr(1), "hex"), this.zmk_tmk_key_type); //remove U in front, then decrypt
		var key_zmk = CryptoHelper.tdes_enc_ecb(zmk_tmk_clear, key_clear);
		
		this.output = (this.key_scheme 
			+ key_lmk.toString("hex")
			+ this.key_scheme_zmk_tmk
			+ key_zmk.toString("hex")
			+ kcv.toString("hex")
			).toUpperCase();
	}
	else{ //no export
		this.output = (this.key_scheme 
			+ key_lmk.toString("hex")
			+ kcv.toString("hex")
			).toUpperCase();
	}

}




module.exports = A0;
