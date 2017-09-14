function ErrorCode(){
	this.SUCCESS = "00";
	this.INVALID_KEY_SCHEME = "26";
	this.INVALID_INPUT_FORMAT_FLAG = "99";
	this.INVALID_KEY_TYPE = "98";
	this.INVALID_KSN_DESCRIPTOR="97";
	this.INVALID_SOURCE_PIN_FORMAT = "96";
	this.INVALID_DEST_PIN_FORMAT = "97";

}


/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
ErrorCode.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
ErrorCode.getInstance = function(){
    if(this.instance === null){
        this.instance = new ErrorCode();
    }
    return this.instance;
}
 
module.exports = ErrorCode.getInstance();