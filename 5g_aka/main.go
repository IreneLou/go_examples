package main

import (
    "fmt"
    "regexp"
    "encoding/hex"
    "free5gc/lib/milenage"
    "free5gc/lib/UeauCommon"
)

type UeRanContext struct {
	Supi               string
	RanUeNgapId        int64
	AmfUeNgapId        int64
	//ULCount            security.Count
	//DLCount            security.Count
	CipheringAlg       uint8
	IntegrityAlg       uint8
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	//AuthenticationSubs models.AuthenticationSubscription
}

func main() {
    /*208093
    supi := "imsi-2089300007487"
    k := "5122250214c33e723a5dd523fc145fc0"
    op := "c9e8763286b5b9ffbdf56e1297d0887b"
    rand := "cbeed9825487941484dfc525d06daba3"
    autn := "3805f711694680007350347df87246a9"
    */
    // 466066
    supi := "imsi-466666100000001"
    k := "808182888485868788898a8b8c8d8e8f"
    op := "97a167ded889b6dfa92d985d77e5c088"
    //rand := "d560c65d69608826db030328aaf96707"
    //autn := "491669bf1c5480005411ef8bc6b071bd"
    rand := "bdfb9caf79249956442a915f6a5785d4"
    autn := "93b4fe7f60198000f966fe70968799ee"
    bin_k, err := hex.DecodeString(k)
    if err != nil {
        panic(err)
    }
    bin_op, err := hex.DecodeString(op)
    if err != nil {
        panic(err)
    }
    bin_rand, err := hex.DecodeString(rand)
    if err != nil {
        panic(err)
    }
    bin_autn, err := hex.DecodeString(autn)
    if err != nil {
        panic(err)
    }

    ue := UeRanContext{}
    ue.Supi = supi
    ue.CipheringAlg = 0
    ue.IntegrityAlg = 2

    opc := make([]byte, 16)
    opc, err = milenage.GenerateOPC(bin_k, bin_op)
    if err != nil {
        panic(err)
    }
    macA, macS := make([]byte, 8), make([]byte, 8)
    ck, ik := make([]byte, 16), make([]byte, 16)
    res := make([]byte, 8)
    ak, akStar := make([]byte, 6), make([]byte, 6)

    // Generate RES, CK, IK, AK, AKstar
    err = milenage.F2345(opc, bin_k, bin_rand, res, ck, ik, ak, akStar)
    if err != nil {
        panic(err)
    }

    SQNxorAK := bin_autn[:6]
    sqn := make([]byte, 6)
    for i := 0; i < len(sqn); i++ {
        sqn[i] = SQNxorAK[i] ^ ak[i]
    }
    amf, err := hex.DecodeString("8000")

    // Generate MAC_A, MAC_S
    err = milenage.F1(opc, bin_k, bin_rand, sqn, amf, macA, macS)
    if err != nil {
        panic(err)
    }


    // derive RES*
    //snName := "5G:mnc093.mcc208.3gppnetwork.org"
    snName := "5G:mnc066.mcc466.3gppnetwork.org"
    key := append(ck, ik...)
    FC := UeauCommon.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
    P0 := []byte(snName)
    P1 := bin_rand
    P2 := res

    kdfVal_for_resStar :=
	UeauCommon.GetKDFValue(key, FC, P0, UeauCommon.KDFLen(P0), P1, UeauCommon.KDFLen(P1), P2, UeauCommon.KDFLen(P2))
    //return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:]

    fmt.Printf("k: %x \n", bin_k)
    fmt.Printf("opc: %x \n", opc)
    fmt.Printf("rand: %x \n", bin_rand)
    fmt.Printf("sqn: %x \n", sqn)
    fmt.Printf("ak: %x \n", ak)
    fmt.Printf("macA: %x \n", macA)
    fmt.Printf("RES*: %x\n", kdfVal_for_resStar[len(kdfVal_for_resStar)/2:])

    ue.DerivateKamf(key, snName, sqn, ak) 
    ue.DerivateAlgKey()

    fmt.Printf("EEA0: %x \n", ue.KnasEnc)
    fmt.Printf("EIA2: %x \n", ue.KnasInt)
    amf, _ = hex.DecodeString("0800")
    amfStr := hex.EncodeToString(amf)
    fmt.Println(amfStr)

    //tmp := make([]uint8, 3)
    tmp := []uint8{0, 1, 2}
    s := tmp[:2]
    s[len(s)-1] |= 0xf0
    fmt.Println(s)
}

func (ue *UeRanContext) DerivateKamf(key []byte, snName string, SQN, AK []byte) {

	FC := UeauCommon.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}
	P1 := SQNxorAK
	Kausf := UeauCommon.GetKDFValue(key, FC, P0, UeauCommon.KDFLen(P0), P1, UeauCommon.KDFLen(P1))
	P0 = []byte(snName)
	Kseaf := UeauCommon.GetKDFValue(Kausf, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))


	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
                panic(err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	P0 = []byte(groups[1])
	L0 := UeauCommon.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := UeauCommon.KDFLen(P1)

	ue.Kamf = UeauCommon.GetKDFValue(Kseaf, UeauCommon.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)

        fmt.Printf("Kausf: %x \n", Kausf)
        fmt.Printf("Kseaf: %x \n", Kseaf)
        fmt.Printf("Kamf: %x \n", ue.Kamf)
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *UeRanContext) DerivateAlgKey() {
	// Security Key
	//P0 := []byte{security.NNASEncAlg}
	P0 := []byte{0x01}
	L0 := UeauCommon.KDFLen(P0)
	P1 := []byte{ue.CipheringAlg}
	L1 := UeauCommon.KDFLen(P1)

	kenc := UeauCommon.GetKDFValue(ue.Kamf, UeauCommon.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(ue.KnasEnc[:], kenc[16:32])

	// Integrity Key
	//P0 = []byte{security.NNASIntAlg}
	P0 = []byte{0x02}
	L0 = UeauCommon.KDFLen(P0)
	P1 = []byte{ue.IntegrityAlg}
	L1 = UeauCommon.KDFLen(P1)

	kint := UeauCommon.GetKDFValue(ue.Kamf, UeauCommon.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(ue.KnasInt[:], kint[16:32])
}

