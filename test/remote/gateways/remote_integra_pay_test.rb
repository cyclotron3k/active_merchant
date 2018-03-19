require 'test_helper'

class RemoteIntegraPayTest < Test::Unit::TestCase
  def setup
    # IntegraPayGateway.wiredump_device = $stdout
    # IntegraPayGateway.wiredump_device.sync = true
    @gateway = IntegraPayGateway.new(fixtures(:integra_pay))
    @amount = 100 # one dollar
    @credit_card = credit_card('4000100011112224')
    @declined_card = credit_card('4000300011112220')
    @options = {
      billing_address: address,
      description: 'Store Purchase'
    }
  end

  def test_successful_purchase
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: id))
    assert_success response
    assert_equal 'S', response.message
    assert_equal id, response.authorization
  end

  def test_duplicate_purchase
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: id))
    assert_success response
    assert_equal 'S', response.message
    assert_equal id, response.authorization

    response = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'processing_error', response.error_code
    assert_equal 'A transaction with the transactionID you have provided already exists', response.message
    assert_equal 'processing_error', response.error_code
  end

  def test_purchase_without_id
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_success response
    assert_equal 'S', response.message
    assert_false response.authorization.nil?

    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_success response
    assert_equal 'S', response.message
    assert_false response.authorization.nil?
  end

  def test_successful_authorize
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: id))
    assert_success response
    assert_equal 'S', response.message
    assert_equal id, response.authorization
  end

  def test_failed_purchase_invalid_card
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount + 31, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'card_declined', response.error_code
    assert_equal 'F - Invalid Credit Card', response.message
    assert_nil response.authorization
  end

  def test_failed_purchase_expired_card
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount + 54, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'expired_card', response.error_code
    assert_equal 'F - Expired Credit Card', response.message
    assert_nil response.authorization
  end

  def test_failed_purchase_declined
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount + 51, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'card_declined', response.error_code
    assert_equal 'F - Transaction Declined', response.message
    assert_nil response.authorization
  end

  def test_failed_purchase_insufficient_funds
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount + 61, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'card_declined', response.error_code
    assert_equal 'F - Insufficient Funds', response.message
    assert_nil response.authorization
  end

  def test_failed_purchase_technical_failure
    id = "Test#%05i" % Random.rand(100000)
    response = @gateway.purchase(@amount + 96, @credit_card, @options.merge(order_id: id))
    assert_failure response
    assert_equal 'processing_error', response.error_code
    assert_equal 'R - Invalid Transaction', response.message
    assert_nil response.authorization
  end

  def test_partial_capture
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    cap_id = "Test#%05i" % Random.rand(100000)
    assert capture = @gateway.capture(@amount-1, auth_id, {order_id: cap_id})
    assert_success capture
    assert_equal 'S - Successful', capture.message
    assert_equal cap_id, capture.authorization
  end

  def test_failed_partial_capture_invalid_amount
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount + 100, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    cap_id = "Test#%05i" % Random.rand(100000)
    assert capture = @gateway.capture(@amount + 11, auth_id, {order_id: cap_id})
    assert_failure capture
    assert_equal 'F - CAPTURE FAILED - Invalid amount', capture.message
    assert_nil capture.authorization
  end

  def test_failed_partial_capture_declined
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount + 100, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    cap_id = "Test#%05i" % Random.rand(100000)
    assert capture = @gateway.capture(@amount + 12, auth_id, {order_id: cap_id})
    assert_failure capture
    assert_equal 'F - CAPTURE FAILED - Process declined', capture.message
    assert_nil capture.authorization
  end

  def test_failed_partial_capture_unable_to_process
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount + 100, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    cap_id = "Test#%05i" % Random.rand(100000)
    assert capture = @gateway.capture(@amount + 13, auth_id, {order_id: cap_id})
    assert_failure capture
    assert_equal 'R - Unable to process at this time', capture.message
    assert_nil capture.authorization
  end

  # def test_verify
  #   verify = @gateway.verify(@credit_card, @options)
  #   assert_success verify
  #   assert_equal 'S', verify.message
  #   puts verify.authorization
  # end

  def test_partial_capture_partial_refund
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    cap_id = "Test#%05i" % Random.rand(100000)
    assert capture = @gateway.capture(@amount-1, auth.authorization, {order_id: cap_id})
    assert_success capture
    assert_equal 'S - Successful', capture.message
    assert_equal cap_id, capture.authorization

    # Will fail if Refunds have not been enabled on your account
    ref_id = "Test#%05i" % Random.rand(100000)
    assert refund = @gateway.refund(@amount-2, auth.authorization, {order_id: ref_id})
    assert_success refund
    assert_equal 'S - Successful', refund.message
    assert_equal ref_id, refund.authorization
  end

  def test_purchase_refund
    purchase_id = "Test#%05i" % Random.rand(100000)
    purchase = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: purchase_id))
    assert_success purchase
    assert_equal 'S', purchase.message
    assert_equal purchase_id, purchase.authorization

    # Will fail if Refunds have not been enabled on your account
    ref_id = "Test#%05i" % Random.rand(100000)
    assert refund = @gateway.refund(@amount, purchase.authorization, {order_id: ref_id})
    assert_success refund
    assert_equal 'S - Successful', refund.message
    assert_equal ref_id, refund.authorization
  end

  def test_purchase_over_refund
    purchase_id = "Test#%05i" % Random.rand(100000)
    purchase = @gateway.purchase(@amount, @credit_card, @options.merge(order_id: purchase_id))
    assert_success purchase
    assert_equal 'S', purchase.message
    assert_equal purchase_id, purchase.authorization

    # Will fail if Refunds have not been enabled on your account
    ref_id = "Test#%05i" % Random.rand(100000)
    assert refund = @gateway.refund(@amount + 1, purchase.authorization, {order_id: ref_id})
    assert_failure refund
    assert_match /processAmountInCents can not be greater than the original transaction amount \(1\.00\)/, refund.message
    assert_nil refund.authorization
  end

  def test_auth_refund
    auth_id = "Test#%05i" % Random.rand(100000)
    auth = @gateway.authorize(@amount, @credit_card, @options.merge(order_id: auth_id))
    assert_success auth
    assert_equal 'S', auth.message
    assert_equal auth_id, auth.authorization

    # Will fail if Refunds have not been enabled on your account
    ref_id = "Test#%05i" % Random.rand(100000)
    assert refund = @gateway.refund(@amount, auth.authorization, {order_id: ref_id})
    assert_failure refund
    assert_equal 'No transaction was found with the information you provided', refund.message
    assert_nil refund.authorization
  end



  # def test_failed_authorize
  #   response = @gateway.authorize(@amount, @declined_card, @options)
  #   assert_failure response
  #   assert_equal 'processing_error', response.error_code
  #   assert_equal 'REPLACE WITH FAILED AUTHORIZE MESSAGE', response.message
  # end

  # def test_failed_capture
  #   response = @gateway.capture(@amount, '')
  #   assert_failure response
  #   assert_equal 'processing_error', response.error_code
  #   assert_equal 'REPLACE WITH FAILED CAPTURE MESSAGE', response.message
  # end

  # def test_successful_refund
  #   purchase = @gateway.purchase(@amount, @credit_card, @options)
  #   assert_success purchase

  #   assert refund = @gateway.refund(@amount, purchase.authorization)
  #   assert_success refund
  #   assert_equal 'REPLACE WITH SUCCESSFUL REFUND MESSAGE', refund.message
  # end

  # def test_partial_refund
  #   purchase = @gateway.purchase(@amount, @credit_card, @options)
  #   assert_success purchase

  #   assert refund = @gateway.refund(@amount-1, purchase.authorization)
  #   assert_success refund
  # end

  # def test_failed_refund
  #   response = @gateway.refund(@amount, '')
  #   assert_failure response
  #   assert_equal 'processing_error', response.error_code
  #   assert_equal 'REPLACE WITH FAILED REFUND MESSAGE', response.message
  # end

  # def test_successful_void
  #   auth = @gateway.authorize(@amount, @credit_card, @options)
  #   assert_success auth

  #   assert void = @gateway.void(auth.authorization)
  #   assert_success void
  #   assert_equal 'REPLACE WITH SUCCESSFUL VOID MESSAGE', void.message
  # end

  # def test_failed_void
  #   response = @gateway.void('')
  #   assert_failure response
  #   assert_equal 'processing_error', response.error_code
  #   assert_equal 'REPLACE WITH FAILED VOID MESSAGE', response.message
  # end

  # def test_successful_verify
  #   response = @gateway.verify(@credit_card, @options)
  #   assert_success response
  #   assert_match %r{REPLACE WITH SUCCESS MESSAGE}, response.message
  # end

  # def test_failed_verify
  #   response = @gateway.verify(@declined_card, @options)
  #   assert_failure response
  #   assert_equal 'processing_error', response.error_code
  #   assert_match %r{REPLACE WITH FAILED PURCHASE MESSAGE}, response.message
  # end

  def test_invalid_login
    gateway = IntegraPayGateway.new(username: 'username', password: 'password')

    response = gateway.purchase(@amount, @credit_card, @options)
    assert_failure response
    assert_equal 'processing_error', response.error_code
    assert_equal 'The username/password is incorrect or has not been granted access to this function', response.message
  end

  def test_transcript_scrubbing
    transcript = capture_transcript(@gateway) do
      @gateway.purchase(@amount, @credit_card, @options)
    end
    transcript = @gateway.scrub(transcript)

    assert_scrubbed(@credit_card.number, transcript)
    assert_scrubbed(@credit_card.verification_value, transcript)
    assert_scrubbed(@gateway.options[:password], transcript)
  end

end
