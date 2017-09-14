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

	var command_handler_class = require("./HostCommands/"+command.toString());
	var command_handler = new command_handler_class();
	command_resp = command_handler.processCommand(command_data);

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
