This is the next version of https://github.com/johnsheehan/TwilioApi. There are minor breaking changes in the REST API wrapper. The current state of this project is 'Release Candidate' and there might be bugs. Please report any using the issue tracker.

<hr />

# Twilio REST API and TwiML Libraries for .NET, ASP.NET, ASP.NET MVC and WebMatrix

Twilio provides a simple HTTP-based API for sending and receiving phone calls and text messages. Learn more at [http://www.twilio.com][0]

## [Twilio REST API Documentation][1]
## [Twilio TwiML Documentation][2]
## [.NET Library Documentation][3] (in progress)

### Sample Usage

    using Twilio;
    var twilio = new TwilioClient("accountSid", "authToken");
    var call = twilio.InitiateOutboundCall("+1123456790", "+15555551212", "http://example.com/handleCall");
    var msg = twilio.SendSmsMessage("+15555551212", "+11234567890", "Can you believe it's this easy to send an SMS?!");

### Silverlight/Windows Phone 7/Asynchronous Requests Sample

    using Twilio;
    var twilio = new TwilioClient("accountSid", "authToken");
    twilio.InitiateOutboundCall("+1123456790", "+15555551212", "http://example.com/handleCall", (call) => {
        // Console.WriteLog(call.Sid);
    });

    twilio.SendSmsMessage("+15555551212", "+11234567890", "Hello!", (msg) => {
        // Console.WriteLine(msg.Sid);
    });

### TwiML Generation with ASP.NET Sample

	var response = new TwilioResponse();
	response.Say("Hello Monkey");
	response.Play("http://demo.twilio.com/hellomonkey/monkey.mp3");
	response.BeginGather(new { numDigits = 1, action = "hello-monkey-handle-key.php", method = "POST" });
	response.Say("To speak to a real monkey, press 1. Press 2 to record your own monkey howl. Press any other key to start over.");
	response.EndGather();

	// ASP.NET MVC when controller inherits from TwilioController
	return TwiML(response);

	// ASP.NET MVC regular controller
	return new TwiMLResult(response);

	// ASP.NET Webforms
	var doc = response.ToXDocument();
    Response.ContentType = "application/xml";
	doc.Save(Response.Output);


[0]: http://www.twilio.com
[1]: http://www.twilio.com/docs/api/rest
[2]: http://www.twilio.com/docs/api/twiml
[3]: https://github.com/johnsheehan/Twilio/wiki