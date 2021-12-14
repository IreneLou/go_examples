package main

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/aper/logger"
	"github.com/free5gc/ngap/ngapType"
)

func main() {
	logger.SetLogLevel(5)
	// /*
	// full
	transfer_str := "0000050082000a0c0bebc2003005f5e100008b000a01f0c0a80718000000030086000100008a00096020000000974001400088001700014000030c00404c4b40204c4b40201e8480200f4240"
	// remove security
	// transfer_str := "0000040082000a0c0bebc2003005f5e100008b000a01f0c0a807180000000300860001000088001700014000030c00404c4b40204c4b40201e8480200f4240"
	// remove qos
	//transfer_str := "0000040082000a0c0bebc2003005f5e100008b000a01f0c0a80718000000030086000100008a0009602000000097400140"
	transfer_bin, err := hex.DecodeString(transfer_str)
	if err != nil {
		fmt.Printf("transfer hex string decode error \n")
	}
	transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
	err = aper.UnmarshalWithParams(transfer_bin, &transfer, "valueExt")
	if err != nil {
		fmt.Printf("transfer decode error \n")
	}
	// */
	/*
		// security_str := "008a0009602000000097400140"
		// ok
		//security_str := "008a00096020"
		security_str := "602000000097400140"
		security_bin, err := hex.DecodeString(security_str)
		if err != nil {
			fmt.Printf("security hex string decode error \n")
		}
		security := ngapType.SecurityIndication{}
		err = aper.UnmarshalWithParams(security_bin, &security, "valueExt")
		// err = aper.UnmarshalWithParams(security_bin, &security, "openType")
		if err != nil {
			fmt.Printf("security decode error  \n")
		}

		/*
			// user_str := "0079400880f8c0a8089701f4"
			// user_str := "400880f8c0a8089701f4"
			user_str := "80f8c0a8089701f4"
			user_bin, err := hex.DecodeString(user_str)
			if err != nil {
				fmt.Printf("user hex string decode error \n")
			}
			user := ngapType.UserLocationInformation{}
			err = aper.UnmarshalWithParams(user_bin, &user, "valueLB:0,valueUB:2")
			// err = aper.UnmarshalWithParams(user_bin, &user, "openType")
			if err != nil {
				fmt.Printf("user decode error \n")
			}
	*/
	/*
		// s := "002e4055000004000a0002000100550002000000260036357e029da7a508027e00670100142e0a00c1ffff917b000a80000a00000d00000300120a81220401010203250908696e7465726e65740079400880f8c0a8089701f4"
		s := "001d0080ec000004000a00020003005500020000004a0080ca00400a747e02ce0d17b0027e00680100652e0a00c211000901000631300101ff01060600c806006459322905010a0a000322040101020379001a01204501010302030600010303060002040306000505030600057b001480000d0408080808000d04080804040010020578250908696e7465726e6574120a40200001114c0000050082000a0c0bebc2003005f5e100008b000a01f0c0a80718000000060086000100008a00096020000000974001400088001700014000030c00404c4b40204c4b40201e8480200f4240006e400a0c77359400303b9aca00"
		msg, err := hex.DecodeString(s)
		if err != nil {
			fmt.Printf("s hex string decode error \n")
		}
		pdu, err := Decoder(msg)
		if err != nil {
			fmt.Printf("pdu decode error \n")
		}
		fmt.Printf("%d", pdu.Present)
	*/
	/*
		qos_str := "0088001700014000030c00404c4b40204c4b40201e8480200f4240"
		qos_bin, err := hex.DecodeString(qos_str)
		if err != nil {
			fmt.Printf("qos hex string decode error \n")
		}
		qos := ngapType.QosFlowSetupRequestList{}
		err = aper.UnmarshalWithParams(qos_bin, &qos, "valueExt")
		if err != nil {
			fmt.Printf("qos decode error \n")
		}
	*/
}

func Decoder(b []byte) (pdu *ngapType.NGAPPDU, err error) {
	pdu = &ngapType.NGAPPDU{}

	err = aper.UnmarshalWithParams(b, pdu, "valueExt,valueLB:0,valueUB:2")
	return
}
