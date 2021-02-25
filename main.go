package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var client *mongo.Client

// SECRET_KEY is token
var SECRET_KEY = []byte("aws12")

// User is a sruct
type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name     string             `json:"name,omitempty" bson:"name,omitempty"`
	Email    string             `json:"email,omitempty" bson:"email,omitempty"`
	Username string             `json:"username,omitempty" bson:"username,omitempty"`
	Password string             `json:"password,omitempty" bson:"password,omitempty"`
}

// Claims struct
type Claims struct {
	Email string
	// Password string
	jwt.StandardClaims
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

// GenerateJWT is used for generating a token
func GenerateJWT(email string) (string, error) {
	// expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		// Password: password,
		StandardClaims: jwt.StandardClaims{

			// ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(SECRET_KEY)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}
func main() {
	fmt.Println("Starting server Connection.....")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	clientOption := options.Client().ApplyURI("mongodb://127.0.0.1:27017")
	client, _ = mongo.Connect(ctx, clientOption)
	router := mux.NewRouter()
	router.HandleFunc("/api/register", register).Methods("POST")
	router.HandleFunc("/api/login", login).Methods("POST")
	http.ListenAndServe(":8000", router)
}
func register(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content type", "application/json")
	var user User
	_ = json.NewDecoder(request.Body).Decode(&user)
	user.Password = getHash([]byte(user.Password))
	collection := client.Database("users").Collection("register")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.InsertOne(ctx, user)
	json.NewEncoder(response).Encode(result)
}
func login(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content type", "application/json")
	var user User
	var dbUser User
	_ = json.NewDecoder(request.Body).Decode(&user)
	fmt.Println(user)
	collection := client.Database("users").Collection("register")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	fmt.Println(err)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	userPass := []byte(user.Password)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		response.Write([]byte(`{"response":"Wrong Password!"}`))
		return
	}
	jwtToken, err := GenerateJWT(user.Email)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	addCookie(response, "Bearer", jwtToken)
}
func addCookie(response http.ResponseWriter, name, value string) {
	// expire := time.Now().Add(ttl)
	cookie := http.Cookie{
		Name:  name,
		Value: value,
		// Expires: expire,
	}
	http.SetCookie(response, &cookie)
}
