package functions

import (
	"fmt"
	"strings"
)

func ResourceID(args ...any) any {
	if len(args) < 2 {
		return nil
	}

	var b strings.Builder

	for _, arg := range args {
		b.WriteByte('/')
		fmt.Fprint(&b, arg)
	}

	return b.String()
}

func ExtensionResourceID(args ...any) any {
	if len(args) < 3 {
		return nil
	}

	var b strings.Builder

	for _, arg := range args {
		b.WriteByte('/')
		fmt.Fprint(&b, arg)
	}

	return b.String()
}

func ResourceGroup(_ ...any) any {
	return fmt.Sprintf(`{
"id": "/subscriptions/%s/resourceGroups/PlaceHolderResourceGroup",
"name": "Placeholder Resource Group",
"type":"Microsoft.Resources/resourceGroups",
"location": "westus",
"managedBy": "%s",
"tags": {
},
"properties": {
  "provisioningState": "Succeeded
}
}`, subscriptionID, managingResourceID)
}
