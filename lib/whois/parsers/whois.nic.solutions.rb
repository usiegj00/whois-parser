#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.nic.solutions server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicSolutions < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found\.$/,
        pattern_reserved: /^This name is reserved by the Registry/
      }

      property_supported :status do
        if reserved?
          :reserved
        elsif available?
          :available
        else
          Array(node("Domain Status"))
        end
      end

      property_supported :registered? do
        !available? && !reserved?
      end

    end

  end
end