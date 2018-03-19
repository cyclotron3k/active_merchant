require 'nokogiri'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IntegraPayGateway < Gateway
      self.live_url = 'https://paymentsapi.io/basic/PayLinkService.svc'
      self.test_url = 'https://sandbox.paymentsapi.io/basic/PayLinkService.svc'

      self.supported_countries = ['US', 'AU', 'NZ']
      self.default_currency = 'AUD'
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]
      self.money_format = :cents

      self.homepage_url = 'https://www.integrapay.com.au/'
      self.display_name = 'IntegraPay'

      def initialize(options={})
        requires!(options, :username, :password)
        super
      end

      MAPPING = {
        purchase: {
          action: 'CreditCardTransaction',
          params: {
            'username'                 => {source: [:options, :username],       required: true},
            'password'                 => {source: [:options, :password],       required: true},
            'processType'              => {value: 'COMPLETE'                                  },
            'transactionID'            => {source: [:options, :order_id],       required: true},
            'transactionDescription'   => {source: [:options, :description]                   },
            'creditCardNumber'         => {source: [:payment, :number],         required: true},
            'creditCardExpiryDate'     => {source: [:expiry_date],              required: true},
            'creditCardCcv'            => {source: [:payment, :verification_value],           },
            'creditCardName'           => {source: [:payment, :name],           required: true},
            'transactionAmountInCents' => {source: [:amount],                   required: true},
            'currency'                 => {source: [:currency]                                },

            # 'transactionSource' => {source: [:options, :transaction_source]},  # currently ignored
            # 'validationLevel' => {source: [:options, :validation_level]},  # currently ignored

            'extraFields'              => {source: [:options, :extra_fields]                  },
            'auditUserIP'              => {source: [:options, :ip]                            },
            'auditUsername'            => {source: [:options, :audit_username]                },

            'payerEmail'               => {source: [:options, :email]                         },
            'payerFirstName'           => {source: [:options, :first_name]                    },
            'payerLastName'            => {source: [:options, :name]                          },
            'payerMobile'              => {source: [:options, :mobile_number]                 },
            'payerPhone'               => {source: [:options, :phone_number]                  },
            'payerUniqueID'            => {source: [:options, :customer_id]                   },

            'payerAddressCountry'      => {source: [:address, :country]                       },
            'payerAddressLine1'        => {source: [:address, :address1]                      },
            'payerAddressLine2'        => {source: [:address, :address2]                      },
            'payerAddressPostCode'     => {source: [:address, :postcode]                      },
            'payerAddressState'        => {source: [:address, :state]                         },
            'payerAddressSuburb'       => {source: [:address, :city]                          },
          }
        },
        authorize: {
          action: 'CreditCardTransaction',
          params: {
            'username'                 => {source: [:options, :username],       required: true},
            'password'                 => {source: [:options, :password],       required: true},
            'processType'              => {value: 'PREAUTH'                                   },
            'transactionID'            => {source: [:options, :order_id],       required: true},
            'transactionDescription'   => {source: [:options, :description]                   },
            'creditCardNumber'         => {source: [:payment, :number],         required: true},
            'creditCardExpiryDate'     => {source: [:expiry_date],              required: true},
            'creditCardCcv'            => {source: [:payment, :verification_value],           },
            'creditCardName'           => {source: [:payment, :name],           required: true},
            'transactionAmountInCents' => {source: [:amount],                   required: true},
            'currency'                 => {source: [:currency]                                },

            # 'transactionSource' => {source: [:options, :transaction_source]},  # currently ignored
            # 'validationLevel' => {source: [:options, :validation_level]},  # currently ignored

            'extraFields'              => {source: [:options, :extra_fields]                  },
            'auditUserIP'              => {source: [:options, :ip]                            },
            'auditUsername'            => {source: [:options, :audit_username]                },

            'payerEmail'               => {source: [:options, :email]                         },
            'payerFirstName'           => {source: [:options, :first_name]                    },
            'payerLastName'            => {source: [:options, :name]                          },
            'payerMobile'              => {source: [:options, :mobile_number]                 },
            'payerPhone'               => {source: [:options, :phone_number]                  },
            'payerUniqueID'            => {source: [:options, :customer_id]                   },

            'payerAddressCountry'      => {source: [:address, :country]                       },
            'payerAddressLine1'        => {source: [:address, :address1]                      },
            'payerAddressLine2'        => {source: [:address, :address2]                      },
            'payerAddressPostCode'     => {source: [:address, :postcode]                      },
            'payerAddressState'        => {source: [:address, :state]                         },
            'payerAddressSuburb'       => {source: [:address, :city]                          },
          }
        },
        capture: {
          action: 'CreditCardTransactionUpdate',
          params: {
            'username'                 => {source: [:options, :username],       required: true},
            'password'                 => {source: [:options, :password],       required: true},
            'processType'              => {value: 'CAPTURE'                                   },
            'processAmountInCents'     => {source: [:amount],                                 },
            'transactionID'            => {source: [:options, :order_id],       required: true},
            'transactionDescription'   => {source: [:options, :description]                   },
            'originalTransactionID'    => {source: [:authorization],            required: true},
            # 'originalBankReceiptID'    => {source: [:authorization],            required: true},

            'originalCreditCardNumber'     => {source: [:options, :original_number],             },
            'originalCreditCardExpiryDate' => {source: [:options, :original_expiry_date],        },
            'originalCreditCardCcv'        => {source: [:options, :original_verification_value], },
            'originalCreditCardName'       => {source: [:options, :original_name],               },

            'extraFields'              => {source: [:options, :extra_fields]                  },
            'auditUsername'            => {source: [:options, :audit_username]                },
            'auditUserIP'              => {source: [:options, :ip]                            },
          }
        },
        refund: {
          action: 'CreditCardTransactionUpdate',
          params: {
            'username'                 => {source: [:options, :username],       required: true},
            'password'                 => {source: [:options, :password],       required: true},
            'processType'              => {value: 'REFUND'                                    },
            'processAmountInCents'     => {source: [:amount],                                 },
            'transactionID'            => {source: [:options, :order_id],       required: true},
            'transactionDescription'   => {source: [:options, :description]                   },
            'originalTransactionID'    => {source: [:authorization],            required: true},
            # 'originalBankReceiptID'    => {source: [:authorization],            required: true},

            'originalCreditCardNumber'     => {source: [:options, :original_number],             },
            'originalCreditCardExpiryDate' => {source: [:options, :original_expiry_date],        },
            'originalCreditCardCcv'        => {source: [:options, :original_verification_value], },
            'originalCreditCardName'       => {source: [:options, :original_name],               },

            'extraFields'              => {source: [:options, :extra_fields]                  },
            'auditUsername'            => {source: [:options, :audit_username]                },
            'auditUserIP'              => {source: [:options, :ip]                            },
          }
        },
      }

      # define the following methods:
      def purchase(money, payment, options={})
        data_sources = {
          :money       => money,
          :payment     => payment,
          :options     => @options.merge(options),
          :amount      => amount(money),
          :currency    => (options[:currency] || currency(money)),
          :expiry_date => sprintf("%04i%02i", payment.year, payment.month),
          :address     => (options[:billing_address] || options[:address]),
        }
        base(MAPPING[:purchase], data_sources)
      end

      def authorize(money, payment, options={})
        data_sources = {
          :money       => money,
          :payment     => payment,
          :options     => @options.merge(options),
          :amount      => amount(money),
          :currency    => (options[:currency] || currency(money)),
          :expiry_date => sprintf("%04i%02i", payment.year, payment.month),
          :address     => (options[:billing_address] || options[:address]),
        }
        base(MAPPING[:authorize], data_sources)
      end

      def capture(money, authorization, options={})
        data_sources  = {:money => money, :authorization => authorization, :options => @options.merge(options), :amount => amount(money), :currency => (options[:currency] || currency(money))}
        base(MAPPING[:capture], data_sources)
      end

      def refund(money, authorization, options={})
        data_sources = {:money => money, :authorization => authorization, :options => @options.merge(options), :amount => amount(money), :currency => (options[:currency] || currency(money))}
        base(MAPPING[:refund], data_sources)
      end

      def base(spec, data_sources)
        # If you don't supply a unique id, then one will be generated for you
        data_sources[:options][:order_id] ||= generate_unique_id

        # Assemble all the required parameters...
        parameters = spec[:params].each_with_object({}) do |(field, definition), obj|
          if definition.key? :value
            obj[field] = definition[:value]
          else
            value = definition[:source].reduce(data_sources) do |memo, search|
              if memo.respond_to? :[]
                memo[search]
              elsif memo.respond_to? search
                memo.send search
              else
                nil
              end
            end

            if value.nil?
              raise "Missing #{definition[:source]}" if definition[:required]
            else
              obj[field] = value unless value.nil?
            end
          end
        end

        commit(spec[:action], parameters)

      end

      # def store(payment, options={})
      # end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        fields = ['creditCardCcv', 'creditCardNumber', 'password'].join ?|
        transcript.gsub(/(<(tns:(?:#{fields}))>)([^<]+)(<\/\2>)/i, '\1[FILTERED]\4')
      end

      private

      def construct_payload(action, parameters)
        body = parameters.map { |k, v| "<tns:#{k}>#{v}</tns:#{k}>" }.join

        <<-XML.each_line.map(&:strip).join
          <?xml version="1.0" encoding="UTF-8"?>
          <env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://tempuri.org/" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
            <env:Body>
              <tns:#{action}>
                #{body}
              </tns:#{action}>
            </env:Body>
          </env:Envelope>
        XML
      end

      def parse_xml(text)
        doc = Nokogiri::XML(text).remove_namespaces!
        convert = lambda do |element|
          if element.text?
            { :text => element.text }
          else
            { element.name => element.children.map(&convert).reduce(&:merge) }
          end
        end
        safe_traverse_hash convert.call(doc), ['document']
      end

      def parse(action, response)
        if /\bxml\b/ === response.content_type

          raw_parsed = parse_xml response.body

          unwrapped = safe_traverse_hash raw_parsed, ['Envelope', 'Body']

          # If the request is successful, the response is provided as a string of XML
          # embedded inside the usual XML response
          xml_in_xml = safe_traverse_hash unwrapped, ["#{action}Response", "#{action}Result", :text]

          if xml_in_xml.nil?
            unwrapped
          else
            parse_xml xml_in_xml
          end
        else
          raise "Invalid response content-type: #{response.content_type}. Was expecting XML"
        end
      end

      def commit(action, parameters)
        url = (test? ? test_url : live_url)

        response = raw_ssl_request(:post, url, construct_payload(action, parameters), headers(action))

        parsed = parse(action, response)

        success = success_from(response, parsed)

        Response.new(
          success,
          message_from(parsed),
          parsed,
          :authorization => (success ? parameters['transactionID'] : nil),
          :avs_result    => nil,
          :cvv_result    => nil,
          :test          => test?,
          :error_code    => error_code_from(response, parsed)
        )
      end

      def headers(action)
        {
          "Content-Type" => "text/xml; charset=utf-8",
          "SOAPAction" => "http://tempuri.org/IPayLinkService/#{action}"
        }
      end

      def success_from(response, parsed)
        (200...300).include?(response.code.to_i) and safe_traverse_hash(parsed, ['response', 'resultID', :text]) == ?S
      end

      def message_from(parsed)
        safe_traverse_hash(parsed, ['Fault', 'faultstring', :text]) || [
          safe_traverse_hash(parsed, ['response', 'resultID', :text]),
          safe_traverse_hash(parsed, ['response', 'resultDescription', :text])
        ].compact.join(' - ')
      end

      def safe_traverse_hash(obj, keys, default=nil)
        keys.reduce(obj) do |memo, key|
          if memo.respond_to?(:key?) and memo.key?(key)
            memo[key]
          else
            return default
          end
        end
      end

      def post_data(action, parameters = {})
      end

      def error_code_from(response, parsed)
        unless success_from(response, parsed)

          identifier = safe_traverse_hash(parsed, ['response', 'resultRejectionTypeID', :text]) || safe_traverse_hash(parsed, ['Fault', 'detail']).keys.first

          key = case identifier
          when 'ArgumentInvalidFault', 'ArgumentMissingFault', 'DuplicateTransactionFault', 'NoExistingAccountDetailsFault',
               'PayerNotFoundFault', 'RefundFailedFault', 'RestrictedDueToPayerStatusFault', 'TooManyTransactionsFault',
               'TransactionNotFoundFault', 'TransactionNotValidFault', 'UnauthorizedAccessFault'
            :processing_error
          when "1", "3", "6", "7", "8"
            :card_declined
          when "4"
            :expired_card
          when "5"
            :processing_error
          else
            # puts "Unmapped error: #{identifier}"
            :processing_error
          end

          # 0 - Successful transaction
          # 1 - Insufficient Funds
          # 3 - Invalid Credit Card
          # 4 - Expired Credit Card
          # 5 - Technical Failure
          # 6 - Transaction Declined
          # 7 - Authority Revoked By Payer
          # 8 - Payer Deceased

          STANDARD_ERROR_CODE[key]

          # :call_issuer
          # :card_declined
          # :config_error
          # :expired_card
          # :incorrect_address
          # :incorrect_cvc
          # :incorrect_number
          # :incorrect_pin
          # :incorrect_zip
          # :invalid_cvc
          # :invalid_expiry_date
          # :invalid_number
          # :pickup_card
          # :processing_error
          # :test_mode_live_card
          # :unsupported_feature

        end
      end
    end
  end
end
