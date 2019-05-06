package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/VictorNine/bitwarden-go/internal/api"
	"github.com/VictorNine/bitwarden-go/internal/auth"
	"github.com/VictorNine/bitwarden-go/internal/common"
	"github.com/VictorNine/bitwarden-go/internal/cors"
	"github.com/VictorNine/bitwarden-go/internal/database/sqlite"
)

var cfg struct {
	initDB              bool
	location            string
	signingKey          string
	jwtExpire           int
	hostAddr            string
	hostPort            string
	disableRegistration bool
	vaultURL            string
}

func init() {
	flag.BoolVar(&cfg.initDB, "init", false, "Initalizes the database.")
	flag.StringVar(&cfg.location, "location", "", "Sets the directory for the database")
	flag.StringVar(&cfg.signingKey, "key", "secret", "Sets the signing key")
	flag.IntVar(&cfg.jwtExpire, "tokenTime", 3600, "Sets the ammount of time (in seconds) the generated JSON Web Tokens will last before expiry.")
	flag.StringVar(&cfg.hostAddr, "host", "", "Sets the interface that the application will listen on.")
	flag.StringVar(&cfg.hostPort, "port", "8000", "Sets the port")
	flag.StringVar(&cfg.vaultURL, "vaultURL", "", "Sets the vault proxy url")
	flag.BoolVar(&cfg.disableRegistration, "disableRegistration", false, "Disables user registration.")
}

func main() {
	db := &sqlite.DB{}
	flag.Parse()

	db.SetDir(cfg.location)
	err := db.Open()
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	// Create a new database
	if cfg.initDB {
		err := db.Init()
		if err != nil {
			log.Fatal(err)
		}
	}

	authHandler := auth.New(db, cfg.signingKey, cfg.jwtExpire)
	apiHandler := api.New(db)
	corsMW := cors.New()

	mux := http.NewServeMux()

	if cfg.disableRegistration == false {
		mux.Handle("/api/accounts/register", corsMW.MiddleWare(http.HandlerFunc(authHandler.HandleRegister)))
	}
	mux.Handle("/identity/connect/token", corsMW.MiddleWare(http.HandlerFunc(authHandler.HandleLogin)))
	mux.Handle("/api/accounts/prelogin", corsMW.MiddleWare(http.HandlerFunc(authHandler.HandlePrelogin)))

	mux.Handle("/api/accounts/keys", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleKeysUpdate))))
	mux.Handle("/api/accounts/profile", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleProfile))))
	mux.Handle("/api/collections", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCollections))))
	mux.Handle("/api/folders", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder))))
	mux.Handle("/api/folders/", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolderUpdate))))
	mux.Handle("/apifolders", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder)))) // The android app want's the address like this, will be fixed in the next version. Issue #174
	mux.Handle("/api/sync", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleSync))))

	mux.Handle("/api/ciphers/import", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleImport))))
	mux.Handle("/api/ciphers", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipher))))
	mux.Handle("/api/ciphers/", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherUpdate))))

	if len(cfg.vaultURL) > 4 {
		proxy := common.Proxy{VaultURL: cfg.vaultURL}
		mux.Handle("/", http.HandlerFunc(proxy.Handler))
	}

	mux.Handle("/api/two-factor/get-authenticator", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(authHandler.GetAuthenticator))))
	mux.Handle("/api/two-factor/authenticator", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(authHandler.VerifyAuthenticatorSecret))))
	mux.Handle("/api/two-factor/disable", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleDisableTwoFactor))))
	mux.Handle("/api/two-factor", corsMW.MiddleWare(authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleTwoFactor))))

	log.Println("Starting server on " + cfg.hostAddr + ":" + cfg.hostPort)
	log.Fatal(http.ListenAndServe(cfg.hostAddr+":"+cfg.hostPort, mux))
}
