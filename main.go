package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/wiliamvj/go-auth-cognito/congnitoClient"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type UserResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	CustomID      string `json:"custom_id"`
	EmailVerified bool   `json:"email_verified"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
	cognitoClient := congnitoClient.NewCognitoClient(os.Getenv("COGNITO_CLIENT_ID"))
	r := gin.Default()
	r.POST("user", func(context *gin.Context) {
		err := CreateUser(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"message": "user created"})
	})
	r.POST("user/confirmation", func(context *gin.Context) {
		err := ConfirmAccount(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"message": "user confirmed"})
	})
	r.POST("user/login", func(context *gin.Context) {
		token, err := SignIn(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"token": token})
	})
	r.GET("user", func(context *gin.Context) {
		user, err := GetUserByToken(context, cognitoClient)
		if err != nil {
			if err.Error() == "token not found" {
				context.JSON(http.StatusUnauthorized, gin.H{"error": "token not found"})
				return
			}
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"user": user})
	})
	fmt.Println("Server is running on port 8080")
	err = r.Run(":8080")
	if err != nil {
		panic(err)
	}
}

func CreateUser(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.User
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}
	err := cognito.SignUp(&user)
	if err != nil {
		return errors.New("could not create use")
	}
	return nil
}

func ConfirmAccount(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.UserConfirmation
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}
	err := cognito.ConfirmAccount(&user)
	if err != nil {
		return errors.New("could not confirm user")
	}
	return nil
}

func SignIn(c *gin.Context, cognito congnitoClient.CognitoInterface) (string, error) {
	var user congnitoClient.UserLogin
	if err := c.ShouldBindJSON(&user); err != nil {
		return "", errors.New("invalid json")
	}
	token, err := cognito.SignIn(&user)
	if err != nil {
		return "", errors.New("could not sign in")
	}
	return token, nil
}

func GetUserByToken(c *gin.Context, cognito congnitoClient.CognitoInterface) (*UserResponse, error) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return nil, errors.New("token not found")
	}
	cognitoUser, err := cognito.GetUserByToken(token)
	if err != nil {
		return nil, errors.New("could not get user")
	}
	user := &UserResponse{}
	for _, attribute := range cognitoUser.UserAttributes {
		switch *attribute.Name {
		case "sub":
			user.ID = *attribute.Value
		case "name":
			user.Name = *attribute.Value
		case "email":
			user.Email = *attribute.Value
		case "custom:custom_id":
			user.CustomID = *attribute.Value
		case "email_verified":
			emailVerified, err := strconv.ParseBool(*attribute.Value)
			if err == nil {
				user.EmailVerified = emailVerified
			}
		}
	}
	return user, nil
}
