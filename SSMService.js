var crypto = require("crypto");
var fs = require('fs');
var LMKManager = require("./LMKManager");

const HEADER_LENGTH = 4;



//constructor
function SSMService(){};


//class functions
SSMService.prototype.processRequest = function(data) {
	//process input data with respective commands
	var offset = 0;
	var msg_length = data.slice(offset, offset+2);  offset+=2;
	var header = data.slice(offset, offset+HEADER_LENGTH);  offset+=HEADER_LENGTH;
	var command = data.slice(offset, offset+2); offset+=2;
	var command_data = data.slice(offset);

	console.log("header: " + header.toString()+"; command:"+command.toString());
	var command_resp; //Buffer Type, doesn't contain header

	switch(command.toString())
	{
		case "A0":
			var A0_class = require("./HostCommands/A0");
			var A0 = new A0_class();
			command_resp = A0.processCommand(command_data);
			break;
		case "M0":
			var M0_class = require("./HostCommands/M0");
			var M0 = new M0_class();
			command_resp = M0.processCommand(command_data);
			break;
		case "M2":
			var M2_class = require("./HostCommands/M2");
			var M2 = new M2_class();
			command_resp = M2.processCommand(command_data);
			break;
		default:
			command_resp = Buffer.from("UC:Unknown Command");
	}

	var length = command_resp.length + HEADER_LENGTH; //header + commnad resposne
	var response_full = Buffer.alloc(length+2);   //length + header + command response

	var offset = 0;

	response_full.writeUInt16BE(length); //two bytes length value
	offset +=2;

	response_full.fill(header, offset, offset+header.length); //header
	offset += header.length;

	response_full.fill(command_resp, offset, offset+command_resp.length); //response from command

	return response_full;
};



/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
SSMService.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
SSMService.getInstance = function(){
    if(this.instance === null){
        this.instance = new SSMService();
    }
    return this.instance;
}
 
module.exports = SSMService.getInstance();
