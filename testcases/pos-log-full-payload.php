<?php
// positive repro - patterns copied verbatim from real-world plugin code
class Pos {
	public function log_request( $method, $api, $masked_secret_key, $request ) {
		WC_Stripe_Logger::debug(
			"Stripe API request: {$method} {$api}",
			[
				'stripe_api_key' => $masked_secret_key,
				'request'        => $request,
			]
		);
	}

	public function log_response( $method, $api, $masked_secret_key, $response_body ) {
		WC_Stripe_Logger::debug(
			"Stripe API response: {$method} {$api}",
			[
				'stripe_api_key'    => $masked_secret_key,
				'stripe_request_id' => 'req_123',
				'response'          => $response_body,
			]
		);
	}

	public function log_webhook_event( $event_type, $event ) {
		WC_Stripe_Logger::debug( 'Webhook received (' . $event_type . ')', [ 'event' => $event ] );
	}

	public function log_validation_failure( $result, $request_headers, $event ) {
		WC_Stripe_Logger::error(
			'Webhook validation failed (' . $result . ')',
			[
				'request_headers' => $request_headers,
				'event'           => $event,
			]
		);
	}

	public function static_log( $request ) {
		My_Logger::info( 'request made', [ 'body' => $request ] );
	}
}
