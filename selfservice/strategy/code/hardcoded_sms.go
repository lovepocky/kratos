package code

import (
	"os"
	"strings"

	"github.com/ory/kratos/identity"
	kratosx "github.com/ory/kratos/x"
)

const (
	HardcodedSMSAddressEnv = "KRATOS_HARDCODED_SMS_ADDRESS"
	HardcodedSMSCodeEnv    = "KRATOS_HARDCODED_SMS_CODE"

	defaultHardcodedSMSAddress = "+8618888888888"
	defaultHardcodedSMSCode    = "123456"
)

func HardcodedSMSAddress() string {
	if value, ok := os.LookupEnv(HardcodedSMSAddressEnv); ok {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return defaultHardcodedSMSAddress
}

func HardcodedSMSCode() string {
	if value, ok := os.LookupEnv(HardcodedSMSCodeEnv); ok {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return defaultHardcodedSMSCode
}

func HardcodedSMSRawCode(via identity.CodeChannel, address string) string {
	if IsHardcodedSMSAddress(via, address) {
		return HardcodedSMSCode()
	}

	return GenerateCode()
}

func HardcodedVerificationRawCode(address *identity.VerifiableAddress) string {
	if IsHardcodedVerifiableAddress(address) {
		return HardcodedSMSCode()
	}

	return GenerateCode()
}

func IsHardcodedSMSAddress(via identity.CodeChannel, address string) bool {
	return via == identity.ChannelTypeSMS && matchesHardcodedSMSAddress(address)
}

func IsHardcodedVerifiableAddress(address *identity.VerifiableAddress) bool {
	return address != nil && address.Via == identity.ChannelTypeSMS && matchesHardcodedSMSAddress(address.Value)
}

func IsHardcodedRecoveryAddress(address *identity.RecoveryAddress) bool {
	return address != nil && address.Via == identity.ChannelTypeSMS && matchesHardcodedSMSAddress(address.Value)
}

func matchesHardcodedSMSAddress(address string) bool {
	return kratosx.NormalizePhoneIdentifier(strings.TrimSpace(address)) == kratosx.NormalizePhoneIdentifier(HardcodedSMSAddress())
}
