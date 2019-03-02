package privateKey

import (
	"github.com/romanornr/crypto-addrgen/bcoins"
	"testing"
)

//func TestNew(t *testing.T) {
//	ltc, _ := bcoins.SelectCoin("LTC")
//	pk, _ := NewWIF(ltc.Network.ChainCgfMainNetParams())
//	net := ltc.Network.ChainCgfMainNetParams()
//	fmt.Println(pk)
//
//	fromwif := "T8VERgAiBcUnRXmWxgVzp6AaH1hKwPQQQeghi3n9ZY6nF59GuTJf"
//	wif, _ := FromWIF(fromwif)
//
//	//chaincfg.Register(ltc.Network.ChainCgfMainNetParams())
//	a, _ := NewPublicKeyFromWIF(*wif, net, true)
//	fmt.Println(a.ScriptAddress())
//
//}

func TestFromWIF(t *testing.T) {
	wif := "T8VERgAiBcUnRXmWxgVzp6AaH1hKwPQQQeghi3n9ZY6nF59GuTJf"
	newWif, _ := FromWIF(wif)

	if newWif.String() != wif {
		t.Error(
			"For", wif,
			"expected", wif,
			"got", newWif.String(),
		)
	}
}

func TestNewPublicKeyFromWIF(t *testing.T) {

	var tests = []struct {
		assetSymbol   string
		addressPrefix string
		wif     string
		compressedPublicKey string
	}{
		{assetSymbol: "via", addressPrefix: "V", wif: "7hm2LyNJJvRP5FAondfNBJBVLZ7iZDXDXM5pSz8P6PGiQZJ3Tpj", compressedPublicKey: "Ved77A1rKsyDNBJveamX8TA8UgqMWuq7c7"}, // viacoin
		{assetSymbol: "ltc", addressPrefix: "L", wif: "T8VERgAiBcUnRXmWxgVzp6AaH1hKwPQQQeghi3n9ZY6nF59GuTJf", compressedPublicKey: "LV7LV7Z4bWDEjYkfx9dQo6k6RjGbXsg6hS"}, // litecoin
	}

	for _, pair := range tests {
		asset, _ := bcoins.SelectCoin(pair.assetSymbol)
		wifString := pair.wif
		wif, _ := FromWIF(wifString)

		// test WIF keys
		if wif.String() != pair.wif {
			t.Error(
				"For", asset.Name,
				"expected", pair.wif,
				"got", wif.String(),
			)
		}

		net := asset.Network.ChainCgfMainNetParams()
		compressedAddress, _ := NewPublicKeyFromWIF(*wif, net, true)

		// test compressed public keys
		if compressedAddress.EncodeAddress() != pair.compressedPublicKey {
			t.Error(
				"For", asset.Name,
				"expected", pair.wif,
				"got", wif.String(),
			)
		}
	}
}
