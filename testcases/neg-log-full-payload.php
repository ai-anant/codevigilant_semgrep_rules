<?php
// negative repro - payloads redacted/masked or no payload key
class Neg {
	public function redacted_connect( $result ) {
		WC_Stripe_Logger::debug(
			'OAuth: Generated connect URL',
			[
				'wcc_response' => self::redact_sensitive_data( $result ),
			]
		);
	}

	public function redacted_state( $state ) {
		WC_Stripe_Logger::error(
			'OAuth: Invalid state',
			[
				'state' => self::redact_string( $state ),
			]
		);
	}

	public function scalar_fields_only( $order_id ) {
		WC_Stripe_Logger::error( 'Order failed: ' . $order_id, [ 'error_message' => 'declined' ] );
	}

	public function no_logger() {
		do_action( 'custom_hook', [ 'request' => $_POST ] );
	}
}
