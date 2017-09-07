var net = require('net');
var ssmservice = require('./SSMService');

var server = net.createServer(); //tcp/ip server



server.on("connection", function(socket){
	var remoteAddress = socket.remoteAddress +":"+ socket.remotePort;
	console.log("new client connected from: " + remoteAddress);

	var data_whole = Buffer.alloc(0) ;

	socket.on("data", function(data){
		data_whole = Buffer.concat([data_whole, data]);
		console.log("data received until now: " + data_whole.toString("hex"));

		//check data completeness
		if(data_whole.length > 2)
		{
			var expected_length = data_whole.readUInt16BE(0); //read first 2 bytes to UInt16
			if(expected_length == data_whole.length-2)
			{
				try{
					//process req
					var resp = ssmservice.processRequest(data_whole);

					//reset
					data_whole = Buffer.alloc(0) ;

					//write to socket
					console.log("resp:"+resp.toString("hex"));
					socket.write(resp);
				}
				catch(err)
				{
					console.log(err);
					socket.destroy();
				}

			}
			else if(expected_length < data_whole.length-2) //extra data received
			{
				console.log("More Data received than expected");
				socket.destroy();
			}
		}
		
	});
	socket.once("close", function(){
		console.log("socket closed");

	});
	socket.on("error", function(error){
		console.log("error..."+error);
	});

});


server.listen(1500, function(){
	console.log("SSM server started at port 1500");
});

