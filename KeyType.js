function KeyType(){
	this.ZMK 		= "000";
	this.TMK 		= "002";
	this.TMK_PCI	= "80D";
	this.IPEK 		= "302";
	this.BDK_TYPE_1 = "009";
	this.BDK_TYPE_2 = "609";
	this.BDK_TYPE_3 = "809";
	this.ZPK		= "001";

}


/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
KeyType.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
KeyType.getInstance = function(){
    if(this.instance === null){
        this.instance = new KeyType();
    }
    return this.instance;
}
 
module.exports = KeyType.getInstance();
