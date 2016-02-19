require 'openssl'
require 'base64'
require 'json'

module Redsys
  class Tpv
    attr_accessor :amount, :language, :order, :currency, :merchant_code, :terminal,
                  :transaction_type, :merchant_url, :url_ok, :url_ko, :sha1, :signature

    def self.tpv_url
      Rails.configuration.redsys_rails[:url]
    end

    def self.signature_version
      Rails.configuration.redsys_rails[:signature_version]
    end

    def initialize(amount, order, language, merchant_url = nil, url_ok = nil, url_ko = nil, merchant_name = nil, product_description = nil)
      amount        ||= 0
      order         ||= 0
      language      ||= '001'
      merchant_url  ||= ''
      url_ok        ||= ''
      url_ko        ||= ''
      merchant_name ||= ''
      product_description ||=''

      @amount = (amount * 100).to_i.to_s
      #TODO: there should be a validation of the order format. So far we only make it a string of 12 positions
      @order = order.to_s.rjust(12, '0')
      @language = language
      @merchant_url = merchant_url
      @url_ok = url_ok
      @url_ko = url_ko
      @merchant_name = merchant_name
      @product_description = product_description
      @currency = Rails.configuration.redsys_rails[:merchant_currency]
      @merchant_code = Rails.configuration.redsys_rails[:merchant_code]
      @terminal = Rails.configuration.redsys_rails[:merchant_terminal]
      @transaction_type = Rails.configuration.redsys_rails[:merchant_transaction_type]
    end

    def merchant_params
      "#{strict_encode64(merchant_params_json)}"
    end

    def merchant_params_json
      merchant_parameters = { 
        :DS_MERCHANT_AMOUNT => @amount,
        :DS_MERCHANT_ORDER => @order,
        :DS_MERCHANT_MERCHANTCODE => @merchant_code,
        :DS_MERCHANT_CURRENCY => @currency,
        :DS_MERCHANT_TRANSACTIONTYPE => @transaction_type,
        :DS_MERCHANT_TERMINAL => @terminal,
        :DS_MERCHANT_MERCHANTURL => @merchant_url,
        :DS_MERCHANT_CONSUMERLANGUAGE => @language,
        :DS_MERCHANT_URLOK => @url_ok,
        :DS_MERCHANT_URLKO => @url_ko,
        :DS_MERCHANT_MERCHANTNAME => @merchant_name,
        :DS_MERCHANT_PRODUCTDESCRIPTION => @product_description
      }
      JSON.generate(merchant_parameters)
    end

    def merchant_signature_3des
      strict_encode64(encrypt_3DES(@order, Base64.strict_decode64(Rails.configuration.redsys_rails[:sha_256_key])))
    end

    def merchant_signature
      calculate_key
      encrypt_mac256(merchant_params, @key)
    end

    def self.response_signature(response_data)
      # For checking the received signature from the gateway
      calculate_key
      urlsafe_encrypt_mac256(response_data, @key)
    end

    # TODO: remove this duplicated functions. They are here because I was unable to access the original functions from the notifications controller, not even using module def
    def self.call_strict_encode64(bin)
      Base64.encode64(bin).tr("\n",'')
    end
    def self.call_urlsafe_encode64(bin)
      call_strict_encode64(bin).tr("+/", "-_")
    end
    def self.call_strict_decode64(str)
      unless str.include?("\n")
        Base64.decode64(str)
      else
        raise(ArgumentError,"invalid base64")
      end
    end
    def self.call_urlsafe_decode64(str)
      call_strict_decode64(str.tr("-_", "+/"))
    end

    private

      def calculate_key
        # support function for getting the key both at sending and at reception
        @key = urlsafe_decode64(Rails.configuration.redsys_rails[:sha_256_key])
        @key = encrypt_3DES(@order, @key)
      end

      def urlsafe_encrypt_mac256(data, key)
        urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data))
      end

    #TODO: Remove when upgraded to a Base64 lib that supports m0 for encoding according to RFC 4648
    def strict_encode64(bin)
      Base64.encode64(bin).tr("\n",'')
#          [bin].pack("m0")
    end
    def urlsafe_encode64(bin)
      strict_encode64(bin).tr("+/", "-_")
    end
    #TODO: Remove when upgraded to a Base64 lib that supports m0 for encoding according to RFC 4648
    def strict_decode64(str)
      unless str.include?("\n")
        Base64.decode64(str)
      else
        raise(ArgumentError,"invalid base64")
      end
#      str.unpack("m0").first
    end
    def urlsafe_decode64(str)
      strict_decode64(str.tr("-_", "+/"))
    end

    def urlsafe_encrypt_mac256(data, key)
      urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data))
    end

    def encrypt_mac256(data, key)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data))
      end
    
      def encrypt_3DES(data, key)
        cipher = OpenSSL::Cipher::Cipher.new('DES3')
        cipher.encrypt
        cipher.key = key
        cipher.padding = 0
        block_length = 8
        data_str = data
        data_str += "\0" until data_str.bytesize % block_length == 0
        output = cipher.update(data_str)
        output << cipher.final
        output
      end
  end
end