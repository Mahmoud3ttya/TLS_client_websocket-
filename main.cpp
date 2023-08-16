
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <fstream>
#include <thread>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;//Combine a config with an endpoint role to produce a fully configured endpoint.
// typedef websocketpp::lib::shared_ptr is used to able c++98 environment to run websocket++ which need c++11 environment and it is evaluate to std::shardptr
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
//WebSocket++ will fill in this placeholder with the connection_hdl when it invokes the handler
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// {"event":"bts:subscribe","data":{"channel":"order_book_btcusd"}}
//connection_hdl is a connection identifier that is more filxable than connection_ptr which is defined in <websocketpp/common/connection_hdl.hpp>
void on_open_bitstamp(client* c, websocketpp::connection_hdl hdl) {
    std::string  msg = "{\n"
                       "    \"event\": \"bts:subscribe\",\n"
                       "    \"data\": {\n"
                       "        \"channel\": \"order_book_btcusd\"\n"
                       "    }\n"
                       "}";
    c->send(hdl,msg,websocketpp::frame::opcode::text);
    c->get_alog().write(websocketpp::log::alevel::app, "Sent Message: "+msg);
}
void on_open_binance(client* c, websocketpp::connection_hdl hdl) {
    std::string  msg = "{\n"
                       "  \"event\": \"subscribe\",\n"
                       "  \"pair\": [\n"
                       "    \"XBT/USD\",\n"
                       "    \"XBT/EUR\"\n"
                       "  ],\n"
                       "  \"subscription\": {\n"
                       "    \"name\": \"ticker\"\n"
                       "  }\n"
                       "}";
    c->send(hdl,msg,websocketpp::frame::opcode::text);
    c->get_alog().write(websocketpp::log::alevel::app, "Sent Message: "+msg);
}

void on_fail(client* c, websocketpp::connection_hdl hdl) {
    c->get_alog().write(websocketpp::log::alevel::app, "Connection Failed");
}
// text from doc "he endpoint method that sends a new message will take as a parameter the hdl of the connection to send the message to."
void on_message_bitstamp(client* c, websocketpp::connection_hdl hdl, client::message_ptr msg) {
    std::ofstream myfile;
    myfile.open ("example66.txt",std::ios_base::app);
    myfile<<msg->get_payload() ;

}
void on_message(client* c, websocketpp::connection_hdl hdl, client::message_ptr msg) {
    std::ofstream myfile2;
    myfile2.open ("example67.txt",std::ios_base::app);
    myfile2<<msg->get_payload() ;
}
void on_close(client* c, websocketpp::connection_hdl hdl) {
    c->get_alog().write(websocketpp::log::alevel::app, "Connection Closed");
}


/// Verify that one of the subject alternative names matches the given hostname
bool verify_subject_alternative_name(const char * hostname, X509 * cert) {
    STACK_OF(GENERAL_NAME) * san_names = NULL;

    san_names = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) {
        return false;
    }

    int san_names_count = sk_GENERAL_NAME_num(san_names);

    bool result = false;

    for (int i = 0; i < san_names_count; i++) {
        const GENERAL_NAME * current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type != GEN_DNS) {
            continue;
        }

        char const * dns_name = (char const *) ASN1_STRING_get0_data(current_name->d.dNSName);

        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
            break;
        }
        // Compare expected hostname with the CN
        result = (strcasecmp(hostname, dns_name) == 0);
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return result;
}

/// Verify that the certificate common name matches the given hostname
bool verify_common_name(char const * hostname, X509 * cert) {
    // Find the position of the CN field in the Subject field of the certificate
    int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
    if (common_name_loc < 0) {
        return false;
    }

    // Extract the CN field
    X509_NAME_ENTRY * common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
    if (common_name_entry == NULL) {
        return false;
    }

    // Convert the CN field to a C string
    ASN1_STRING * common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        return false;
    }

    char const * common_name_str = (char const *) ASN1_STRING_get0_data(common_name_asn1);

    // Make sure there isn't an embedded NUL character in the CN
    if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
        return false;
    }

    // Compare expected hostname with the CN
    return (strcasecmp(hostname, common_name_str) == 0);
}

bool verify_certificate(const char * hostname, bool preverified, boost::asio::ssl::verify_context& ctx) {

    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());

    if (depth == 0 && preverified) {
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

        if (verify_subject_alternative_name(hostname, cert)) {
            return true;
        } else if (verify_common_name(hostname, cert)) {
            return true;
        } else {
            return false;
        }
    }

    return preverified;
}

context_ptr on_tls_init(const char * hostname, websocketpp::connection_hdl) {
    context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}
void getbitstamp(std::string URL)
{
    client c;
    std::string uri=URL;
    std::string msg;

    std::string hostname = uri.substr(6,uri.length());

    try {
        // set  logging behavior to silent by clearing all of the access and error logging channels.
        c.clear_access_channels(websocketpp::log::alevel::frame_header);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);
        c.set_error_channels(websocketpp::log::elevel::all);
        // initialize the asio transport system underlying the endpoint and set it to perpetual mode
        c.init_asio();
        c.start_perpetual();

        // Register our handlers Ws://echo.websocket.org
        //open and a fail handler will be used to track whether each connection was successfully opened or failed. If it successfully opens, we will gather some information from the opening handshake
        c.set_open_handler(bind(&on_open_bitstamp,&c,::_1));//set the handler to be called when a new connection is open
        c.set_fail_handler(bind(&on_fail,&c,::_1));//set the handler to be called when a connection fails to connect
        c.set_message_handler(bind(&on_message_bitstamp,&c,::_1,::_2));//The message handler is called after a new message has been received.
        c.set_close_handler(bind(&on_close,&c,::_1));//The close handler is called immediately after the connection is closed.
        c.set_tls_init_handler(bind(&on_tls_init, hostname.c_str(), ::_1));//The tls init handler is called when needed to request a TLS context for the library to use. A TLS init handler must be set and it must return a valid TLS context in order for this endpoint to be able to initialize TLS connections

        /*
         * The connect method
        A new WebSocket connection is initiated via a three step process. First, a connection request is created by endpoint::get_connection(uri). Next, the connection request is configured. Lastly, the connection request is submitted back to the endpoint via endpoint::connect() which adds it to the queue of new connections to make.

        Terminology <tt>connection_ptr</tt>
        WebSocket++ keeps track of connection related resources using a reference counted shared pointer. The type of this pointer is endpoint::connection_ptr. A connection_ptr allows direct access to information about the connection and allows changing connection settings. Because of this direct access and their internal resource management role within the library it is not safe for end applications to use connection_ptr except in the specific circumstances detailed below.

        When is it safe to use connection_ptr?

        After endpoint::get_connection(...) and before endpoint::connect(): get_connection returns a connection_ptr. It is safe to use this pointer to configure your new connection. Once you submit the connection to connect you may no longer use the connection_ptr and should discard it immediately for optimal memory management.
        During a handler: WebSocket++ allows you to register hooks / callbacks / event handlers for specific events that happen during a connection's lifetime. During the invocation of one of these handlers the library guarantees that it is safe to use a connection_ptr for the connection associated with the currently running handler.*/
        websocketpp::lib::error_code ec;// will return the error massage
        // Create a connection to the given URI and adds it to the queue of new connections
        //websocket_endpoint::connect() begins by calling endpoint::get_connection() using a uri passed as a parameter. Additionally, an error output value is passed to capture any errors that might occur during.
        client::connection_ptr con  = c.get_connection(uri, ec);

        c.connect(con);
        c.get_alog().write(websocketpp::log::alevel::app, "Connecting to " + uri);
        // Start the ASIO io_service run loop
        c.run();
        /*
         Terminology: error handling: exceptions vs error_code
         WebSocket++ uses the error code system defined by the C++11 <system_error> library. It can optionally fall back to a similar system provided by the Boost libraries. All user facing endpoint methods that can fail take an error_code in an output parameter and store the error that occured there before returning. An empty/default constructed value is returned in the case of success.

         Exception throwing varients All user facing endpoint methods that take and use an error_code parameter have a version that throws an exception instead. These methods are identical in function and signature except for the lack of the final ec parameter. The type of the exception thrown is websocketpp::exception. This type derives from std::exception so it can be caught by catch blocks grabbing generic std::exceptions. The websocketpp::exception::code() method may be used to extract the machine readable error_code value from an exception.

         For clarity about error handling the utility_client example uses exclusively the exception free varients of these methods. Your application may choose to use either.
         */
    } catch (const std::exception & e) {
        std::cout << e.what() << std::endl;
    }
    catch (websocketpp::lib::error_code e) {
        std::cout << e.message() << std::endl;
    } catch (...) {
        std::cout << "other exception" << std::endl;
    }
}
void getkraken(std::string URL)
{
    client c;
    std::string uri=URL;
    std::string msg;

    std::string hostname = uri.substr(6,uri.length());

    try {
        // set logging policy if needed
        c.clear_access_channels(websocketpp::log::alevel::frame_header);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);
        c.set_error_channels(websocketpp::log::elevel::all);
        // Initialize ASIO
        c.init_asio();
        c.start_perpetual();

        // Register our handlers Ws://echo.websocket.org
        c.set_open_handler(bind(&on_open_binance,&c,::_1));
        c.set_fail_handler(bind(&on_fail,&c,::_1));
        c.set_message_handler(bind(&on_message,&c,::_1,::_2));
        c.set_close_handler(bind(&on_close,&c,::_1));
        c.set_tls_init_handler(bind(&on_tls_init, hostname.c_str(), ::_1));
        // Create a connection to the given URI and queue it for connection once
        // the event loop starts
        websocketpp::lib::error_code ec;
        client::connection_ptr con  = c.get_connection(uri, ec);
        c.connect(con);
        c.get_alog().write(websocketpp::log::alevel::app, "Connecting to " + uri);
        // Start the ASIO io_service run loop
        c.run();
    } catch (const std::exception & e) {
        std::cout << e.what() << std::endl;
    }
    catch (websocketpp::lib::error_code e) {
        std::cout << e.message() << std::endl;
    } catch (...) {
        std::cout << "other exception" << std::endl;
    }
}
int main() {
    std::string BitstampURL = "wss://ws.bitstamp.net/";
    std::string KrakenURL = "wss://ws.kraken.com";
    std::thread KrakenThread(getkraken, KrakenURL);
    std::thread BitstampThread(getbitstamp, BitstampURL);

    KrakenThread.join();
    BitstampThread.join();
}
