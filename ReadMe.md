# Kubernetes OIDC Authentication(Keycloak) + LDAP + GUI (Openshift Origin Console)

### Summary
In this repository you will find how to integrate OIDC Provider(Keycloak is used in this example) with Kubernetes, then integrate the OIDC Provider and LDAP. It will depend on the provider itself, Keycloak has a way to integrate so we use it for our example.

After you do the integrations above, you will have to use **kubectl** client to reach the cluster. 
As its in the header, the next step will be making a console which has greate abilites, the **Openshift Origin Console UI**.

The console UI will be made available to end user for authenticating through OIDC Provider. Since we use Keycloak, we will be able to reach cluster through LDAP authentication.

Let's get into first phase of the authentication, integrating Kubernetes with OIDC Provider

## Kubernetes + OIDC Integration
You will be able to test this integration with [Katacoda's Kubernetes Playground](https://www.katacoda.com/courses/kubernetes/playground) and online [Keycloak Provider](https://realms.please-open.it/). So, you will not need a running Kubernetes Cluster or Keycloak instance to experience it.

- First thing to do is creating an account on https://realms.please-open.it to create our own Keycloak Realm. (It is very straightforward, I used my Github account to create one easily)
- After you login, you will create new Realm. I named the realm as k8s-auth as an example.

![2](https://user-images.githubusercontent.com/59168275/147535904-e7fef9ef-022c-4c9c-bdc9-2090805e4800.gif)
- You will notice that the realm name is highlighted, click it and you will be redirected to the Keycloak Realm. What we need is Issuer URL and client name. When a realm is created, default clients is created too. We will use default client named as **account** for this example. We have few steps to do it this step;
	1. Create new scopes as **openid**(is needed for OIDC Authentication to get **id_token**) and **groups**(will be used with Openshift Origin Console). And after that map those scopes in the clients settings.
	2. Turn on **Direct Access Grants Enabled** settings to get id token with curl command
	3. Add "*" to **Valid Redirect URIs**, it will be used for Openshift Console UI in later.
	4. Make the **account** client confidential and get its **client secret**

![3](https://user-images.githubusercontent.com/59168275/147538062-0a97d55a-1759-493e-998f-1172091e4a92.gif)


- We will also create a test-user and give a permanent password to see if the authentication works on cluster. I gave **1** as the password :)

![4](https://user-images.githubusercontent.com/59168275/147550952-02d552e6-0e5a-4834-8ae6-ba25c39fd462.gif)

- Now we need to get issuer-url of our Realm's from OpenID endpoint like in below.

![5](https://user-images.githubusercontent.com/59168275/147548949-228d1370-3390-42ec-ad93-f58c39119114.gif)
 

- Next step will be configuring the kube-apiserver. If you have installed kubernetes cluster with **kubeadm** way, you will edit **/etc/kubernetes/manifests/kube-apiserver.yml** file. We will edit the file in Katacoda's playground and wait for a minute to let kube-apiserver restart. 

```yaml
    - --oidc-issuer-url=https://app.please-open.it/auth/realms/<YOUR-REALM>
    - --oidc-client-id=account
    - --oidc-username-claim=preferred_username # It maps the Keycloak's prefferred_username claim as user object in Kubernetes Cluster
    - '--oidc-username-prefix=oidc:'
    - '--oidc-groups-prefix=oidc:'
    #- --oidc-groups-claim= # You should use this claim for making it available to the cluster as group object"
    #- --oidc-ca-file=/etc/kubernetes/pki/wildcard/oidc-ca.crt # You should use when your Keycloak instance signed by your own authority.

# NOTE FOR OIDC CA File from K8S Documentation:
# A note about requirement #3 above, requiring a CA signed certificate.
# If you deploy your own identity provider (as opposed to one of the
# cloud providers like Google or Microsoft) you MUST have your identity
# provider's web server certificate signed by a certificate with the CA
# flag set to TRUE, even if it is self signed. This is due to GoLang's
# TLS client implementation being very strict to the standards around
# certificate validation. If you don't have a CA handy, you can use this
# script from the Dex team to create a simple CA and a signed certificate
# and key pair. Or you can use this similar script that generates SHA256
# certs with a longer life and larger key size.
```
![6](https://user-images.githubusercontent.com/59168275/147549023-ff82b22d-d623-4efb-b98b-a43b1df6784c.gif)

- After that you need an id_token and refresh_token, you can get it like the example below. 
		- Not that I have used **jq** here.

```bash
## Enter OIDC properties here
OIDC_TOKEN_ENDPOINT_URL="https://app.please-open.it/auth/realms/<YOUR-REALM>/protocol/openid-connect/token"
OIDC_CLIENT_ID="account"
OIDC_CLIENT_SECRET="<CLIENT SECRET>"
OIDC_TEST_USER="test-user"
OIDC_TEST_PASSWORD="<TEST-USER-PASSWORD>"

## We will use refresh_token and id_token from this reply.
OIDC_TOKENS=$(
	curl -X POST -s \
		-H "Content-Type:application/x-www-form-urlencoded" \
		-d "scope=openid" \
		-d "grant_type=password" \
		-d "client_id=${OIDC_CLIENT_ID}" \
		-d "client_secret=${OIDC_CLIENT_SECRET}" \
		-d "username=${OIDC_TEST_USER}" \
		-d "password=${OIDC_TEST_PASSWORD}" \
		"${OIDC_TOKEN_ENDPOINT_URL}"
)

## Define id_token and refresh_token
OIDC_TEST_USER_ID_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .id_token)
OIDC_TEST_USER_REFRESH_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .refresh_token)
```

- We have tokens, now we can use them to login to cluster.
```bash
kubectl config set-credentials "${OIDC_TEST_USER}" \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url="${OIDC_ISSER_URL}" \
   --auth-provider-arg=client-id="${OIDC_CLIENT_ID}" \
   --auth-provider-arg=client-secret="${OIDC_CLIENT_SECRET}" \
   --auth-provider-arg=refresh-token="${OIDC_TEST_USER_REFRESH_TOKEN}" \
   --auth-provider-arg=id-token="${OIDC_TEST_USER_ID_TOKEN}" 
   # --auth-provider-arg=idp-certificate-authority= # When you have your own OIDC instance with signed you own CA, use this option

## Create your own context with the user you created above
kubectl config set-context test-user-context --user=test-user --cluster=kubernetes

## Before switching to test user, let's give a rolebinding to it to view resources in default namespace
kubectl create rolebinding test-user-view --clusterrole=view --user="oidc:test-user"

## After that you can switch to the test-user
kubectl config use-context test-user-context

## Test getting the pod of default and kube-system namespace, you will see that test-user will not be able to see resources of kube-system namespace
kubectl get po -n default
# No resources found in default namespace.
kubectl get po -n kube-system
#Error from server (Forbidden): pods is forbidden: User "oidc:test-user" cannot list resource "pods" in API group "" in the namespace "kube-system"
```

![7](https://user-images.githubusercontent.com/59168275/147554833-68e74e89-51df-434a-8297-1859e1658d6d.gif)

- This is the end of the OIDC integration of Kubernetes. Next is integrating Keycloak with LDAP to authenticate Kubernetes Cluster.



References:
1. https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuring-the-api-server (Kubernetes-OIDC Integration)
2. https://www.janua.fr/ldap-integration-with-keycloak/ (Keycloak-LDAP Integration)
3. https://www.zflexldapadministrator.com/index.php/blog/82-free-online-ldap (Free LDAP Test Server)
