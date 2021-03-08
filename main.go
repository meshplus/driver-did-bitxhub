package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

type Info struct {
	Method  string // method name
	Owner   string // owner of the method, is a did
	DocAddr string // address where the doc file stored
	DocHash []byte // hash of the doc file
	Status  string // status of method
}

type PubKey struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	PublicKeyPem string `json:"publicKeyPem"`
}

// Auth .
type Auth struct {
	PublicKey []string `json:"publicKey"` // ID of PublicKey
}

// BasicDoc is the fundamental part of doc structure
type BasicDoc struct {
	ID             string      `json:"id"`
	Type           string      `json:"type"`
	Created        string      `json:"created"`
	Updated        string      `json:"updated"`
	Controller     string      `json:"controller"`
	PublicKey      []PubKey    `json:"publicKey"`
	Authentication []Auth      `json:"authentication"`
	Service        interface{} `json:"service"`
}

// Bytes2Struct .
func Bytes2Struct(b []byte, s interface{}) error {
	buf := bytes.NewBuffer(b)
	err := gob.NewDecoder(buf).Decode(s)
	if err != nil {
		return fmt.Errorf("gob decode err: %w", err)
	}
	return nil
}

func WrongResponse(ctx *gin.Context, code int, message string) {
	ctx.JSON(http.StatusOK, gin.H{
		"code":    code,
		"message": message,
	})
}

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	r := gin.Default()
	privKey, err := asym.GenerateKeyPair(crypto.Secp256k1)
	if err != nil {
		panic(err)
	}
	client, err := rpcx.New(
		rpcx.WithNodesInfo(&rpcx.NodeInfo{Addr: "8.136.11.172:60011"}),
		rpcx.WithPrivateKey(privKey),
		rpcx.WithIPFSInfo([]string{"http://8.136.11.172:15001", "http://8.136.11.172:25001", "http://8.136.11.172:35001", "http://8.136.11.172:45001"}),
	)
	if err != nil {
		panic(err)
	}

	r.GET("/1.0/identifiers/:did", func(ctx *gin.Context) {
		did := ctx.Param("did")
		logrus.WithField("did", did).Info("Resolve did")

		args := []*pb.Arg{rpcx.String(did)}
		res, err := client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Resolve", nil, args...)
		if err != nil {
			logrus.WithField("err", err).Error("Get ipfs address from bitxhub")
			WrongResponse(ctx, -10000, err.Error())
			return
		}

		info := &Info{}
		err = Bytes2Struct(res.Ret, info)
		if err != nil {
			logrus.WithField("err", err).Error("Unmarshal data from bitxhub")
			WrongResponse(ctx, -10001, err.Error())
			return
		}

		hash := strings.TrimLeft(info.DocAddr, "data:")
		hash = strings.Replace(hash, `"`, "", -1)
		hash = strings.TrimSpace(hash)

		logrus.WithField("address", hash).Info("Get document from ipfs")
		resp, err := client.IPFSGet(fmt.Sprintf("/ipfs/%s", hash))
		if err != nil {
			logrus.WithField("err", err).Error("Get document from ipfs")
			WrongResponse(ctx, -10002, err.Error())
			return
		}

		doc := &BasicDoc{}
		if err := json.Unmarshal(resp.GetData(), doc); err != nil {
			logrus.WithField("err", err).Error("Unmarshal document data")
			WrongResponse(ctx, -10003, err.Error())
			return
		}

		ctx.JSON(http.StatusOK, doc)
	})

	err = r.Run(":8889")
	if err != nil {
		panic(err)
	}
}
