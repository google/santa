#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_CLIENT_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_CLIENT_H

#include <cstddef>

#import <EndpointSecurity/EndpointSecurity.h>

namespace santa::santad::event_providers::endpoint_security {

class Client {
public:
	explicit Client(es_client_t* client,
                                  es_new_client_result_t result)
      : client_(client), result_(result) {}
  explicit Client(std::nullptr_t c)
      : client_(nullptr), result_(ES_NEW_CLIENT_RESULT_ERR_INTERNAL) {}
  Client()
      : client_(nullptr), result_(ES_NEW_CLIENT_RESULT_ERR_INTERNAL) {}

	virtual ~Client() {
		if (client_) {
			es_delete_client(client_);
		}
	}

	Client(Client&& other) {
		client_ = other.client_;
    result_ = other.result_;
		other.client_ = nullptr;
    other.result_ = ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
	}

	void operator=(Client&& rhs) {
    client_ = rhs.client_;
    result_ = rhs.result_;
    rhs.client_ = nullptr;
    rhs.result_ = ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
  }

	Client(const Client& other) = delete;
	void operator=(const Client& rhs) = delete;

  bool IsConnected() {
    return client_ != nullptr && result_ == ES_NEW_CLIENT_RESULT_SUCCESS;
  }

  es_new_client_result_t NewClientResult() { return result_; }
  es_client_t* Get() const { return client_; }

private:
	es_client_t *client_;
  es_new_client_result_t result_;
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
