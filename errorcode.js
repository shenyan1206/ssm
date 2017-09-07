function ErrorCode(){
	this.SUCCESS = "00";
	this.INVALID_KEY_SCHEME = "26";

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