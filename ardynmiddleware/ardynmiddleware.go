package ardynmiddleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/ardynlabs/ardyncommon/ardynjwt"
	"github.com/ardynlabs/ardyncommon/ardynstructs"
	"github.com/gin-gonic/gin"
)

//-------------------------------------------------------------

type ArdynMiddleware struct {
	Jwt *ardynjwt.ArdynJwt
}

//-------------------------------------------------------------

func (amw *ArdynMiddleware) Authorize(c *gin.Context) {

	var response ardynstructs.ArdynDefaultResponse

	const BEARER_SCHEMA = "Bearer"

	authHeader := c.GetHeader("Authorization")

	if len(authHeader) < 1 {

		log.Println("No authorization header found.")

		response.Code = http.StatusUnauthorized

		response.Message = "No authorization header found."

		c.JSON(response.Code, response)

		c.Abort()

		return

	}

	tokenString := strings.TrimSpace(authHeader[len(BEARER_SCHEMA):])

	// Does the bearer token exist?
	if len(tokenString) == 0 {

		response.Code = http.StatusUnauthorized

		response.Message = "No bearer token found."

		c.JSON(response.Code, response)

		c.Abort()

		return

	}

	// All ok. Now validate the token and get the token data (user's data in this case)
	tokenData, err := amw.Jwt.Validate(tokenString)

	log.Println(tokenData)

	if err != nil {

		log.Println("Token Error: ", err)

		response.Code = http.StatusUnauthorized

		response.Message = "Invalid or expired token found. Please try signing in again."

		response.Error = err.Error()

		c.JSON(response.Code, response)

		c.Abort()

		return

	}

	c.Set("userid", tokenData.UserId)
	c.Set("firstname", tokenData.Firstname)
	c.Set("lastname", tokenData.Lastname)
	c.Set("email", tokenData.Email)
	c.Set("roles", tokenData.Roles)

	c.Next()

}

//-------------------------------------------------------------
/*
func AuthorizeWithRoles(chkRoles []string) gin.HandlerFunc {

}
*/
//-------------------------------------------------------------
