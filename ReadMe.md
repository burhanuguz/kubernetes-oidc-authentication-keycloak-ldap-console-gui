# Kubernetes OIDC Authentication(Keycloak) + LDAP + GUI (Openshift Origin Console)

### Summary
In this repository you will find how to integrate OIDC Provider(Keycloak is used in this example) with Kubernetes, then integrate the OIDC Provider and LDAP(It solely depends on the provider itself, Keycloak has a way to integrate so we use it for our example).

After you do the integrations above, you can use **kubectl** client to reach the cluster. 
As its in the header, the next step will be making a console which has great capabilites, the **Openshift Origin Console UI**.

The console UI will be made available to end user for authenticating through OIDC Provider. Since we use Keycloak, we will be able to reach cluster through LDAP authentication.

Let's get into first phase of the authentication, integrating Kubernetes with OIDC Provider

## Kubernetes + OIDC Integration
You will be able to test this integration with [Katacoda's Kubernetes Playground](https://www.katacoda.com/courses/kubernetes/playground) and online [Keycloak Provider](https://realms.please-open.it/). So, you will not need a running Kubernetes Cluster or Keycloak instance to experience it.

- First thing to do is creating an account on https://realms.please-open.it to create our own Keycloak Realm. (It is very straightforward, I used my Github account to create one easily)
- After you login, you will create new Realm. I named the realm as k8s-auth as an example.

<p align="center">
  <img width="769" height="461" src="https://user-images.githubusercontent.com/59168275/147535904-e7fef9ef-022c-4c9c-bdc9-2090805e4800.gif">
</p>

- You will notice that the realm name is highlighted, click it and you will be redirected to the Keycloak Realm. What we need is Issuer URL and client name. When a realm is created, default clients is created too. We will use default client named as *account* for this example. We have few steps to do it this step;
	1. Create new scopes as **openid**(is needed for OIDC Authentication to get **id_token**) and **groups**(will be used to get groups and also its prerequisite for **Openshift Origin Console**). And after that map those scopes as default scope settings for newly created clients. We will spefically add the scopes for the *account* client because its already created.
	2. Turn on **Direct Access Grants Enabled** settings to get id token with curl command.
	3. Add '**\***' to **Valid Redirect URIs**, it will be used for *Openshift Console UI* in later(You can specifically add your own Redirect URI to make it more secure).
	4. Make the **account** client confidential and get its **client secret**
	5. Create a new mapper to get **group** information with claim named **"groups"** in the *id_token*  (You will see an example how variables got below)
		-	Note that, switch off *Full Group Path* on *Groups* Mapper to get only group named as desired.

<p align="center">
  <img width="" height="" src="https://user-images.githubusercontent.com/59168275/147847881-f8d7db97-f85b-4218-8a9c-bc3e09822723.gif">
</p>

- We will also create a **test-group** and a **test-user**. Add **test-user** to **test-group** and give a permanent password to see if the authentication works on cluster. I gave **1** as the password :)
	- Note that I switched off **Temporary** setting when creating password for the user to make password permanent.

<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147847878-0893fdae-175c-458b-83ec-20f0bbe4e969.gif">
</p>

- Now we need to get **issuer-url** and **token-endpoint-url** of our Realm's from **OpenID endpoint** like in below.

<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147847900-0460d55c-781b-4f8c-9a7d-2efdcc07a73a.gif">
</p>

- After that you can get **id_token** and **refresh_token**. We will take a look what is inside in our **id_token** from
	- Note that I have used **jq** here.
```bash
## Enter OIDC properties here
OIDC_ISSER_URL="https://app.please-open.it/auth/realms/<YOUR-REALM>"
OIDC_TOKEN_ENDPOINT_URL="https://app.please-open.it/auth/realms/<YOUR-REALM>/protocol/openid-connect/token"
OIDC_CLIENT_ID="account"
OIDC_CLIENT_SECRET="<CLIENT SECRET>"
OIDC_USER="<TEST-USER>"
OIDC_GROUP="<TEST-GROUP>"
OIDC_PASSWORD="<TEST-USER-PASSWORD>"

## We will use refresh_token and id_token from this reply.
OIDC_TOKENS=$(
    curl -X POST -s \
        -H "Content-Type:application/x-www-form-urlencoded" \
        -d "scope=openid" \
        -d "grant_type=password" \
        -d "client_id=${OIDC_CLIENT_ID}" \
        -d "client_secret=${OIDC_CLIENT_SECRET}" \
        -d "username=${OIDC_USER}" \
        -d "password=${OIDC_PASSWORD}" \
        "${OIDC_TOKEN_ENDPOINT_URL}"
)

## Define id_token and refresh_token
OIDC_USER_ID_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .id_token)
OIDC_USER_REFRESH_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .refresh_token)
```

- Check the *id_token* on [JWT.IO](https://jwt.io/) like in this example. You will notice that the **groups** and **preferred_username** properties has the values we wanted. We will login to cluster and give **RBAC** with respect to this **username** and **group** properties. **Groups** property will only come after you add it to **mapper** on client

<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147847902-602f7704-c10f-4e71-bd9a-95fbcdbd7a94.gif">
</p>


- Next step will be configuring the kube-apiserver. If you have installed kubernetes cluster with **kubeadm** way, you will edit **/etc/kubernetes/manifests/kube-apiserver.yml** file. Use the **preferred_username** property for **username-claim** and **groups** property for **groups-claim**. We will edit the file in Katacoda's playground and wait for a minute to let kube-apiserver restart. 

```yaml
spec:
  containers:
  - command:
	- kube-apiserver
	- ...
	- --client-ca-file=/etc/kubernetes/pki/ca.crt
	## Start editing after this line
    - --oidc-issuer-url=https://app.please-open.it/auth/realms/<YOUR-REALM>
    - --oidc-client-id=account
    - --oidc-username-claim=preferred_username # It maps the Keycloak's prefferred_username claim as user object in Kubernetes Cluster
    - --oidc-groups-claim=groups # Groups will be known in kubernetes with this prefix
    - '--oidc-username-prefix=oidc-user:' # Users will be known in kubernetes with this prefix
    - '--oidc-groups-prefix=oidc-group:' # Groups will be known in kubernetes with this prefix
    #- --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt # You should use when your Keycloak instance signed by your own authority.
    - ...

# NOTE FOR OIDC CA File from K8S Documentation:
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
<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147848176-029384c8-d802-4e04-bb07-1e95e971afdd.gif">
</p>

- We have tokens, now we can use them to login to cluster.
```bash
kubectl config set-credentials "${OIDC_USER}" \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url="${OIDC_ISSER_URL}" \
   --auth-provider-arg=client-id="${OIDC_CLIENT_ID}" \
   --auth-provider-arg=client-secret="${OIDC_CLIENT_SECRET}" \
   --auth-provider-arg=refresh-token="${OIDC_USER_REFRESH_TOKEN}" \
   --auth-provider-arg=id-token="${OIDC_USER_ID_TOKEN}" 
   # --auth-provider-arg=idp-certificate-authority=${HOME}/oidc-ca.crt # When you have your own OIDC instance with signed your own CA, use this option to trust the OIDC site

## Create context with the user created
kubectl config set-context "${OIDC_USER}-context" --user="${OIDC_USER}" --cluster=kubernetes

## Create namespaces named as 'test-group-authentication' and 'test-user-authentication' to test authentication with both group and user name based authentication.
kubectl create namespace test-group-authentication
kubectl create namespace test-user-authentication

## Let's give a rolebinding to specifically to user and group to view resources in created namespaces respectively
kubectl create rolebinding "${OIDC_USER}-view"  --clusterrole=view --user="oidc-user:${OIDC_USER}"    --namespace test-group-authentication
kubectl create rolebinding "${OIDC_GROUP}-view" --clusterrole=view --group="oidc-group:${OIDC_GROUP}" --namespace test-user-authentication

## After that you can switch to the ${OIDC_USER}
kubectl config use-context "${OIDC_USER}"-context

## Test getting the pod of 'test-group-authentication', 'test-user-authentication' and 'kube-system' namespace

kubectl get pod --namespace test-group-authentication
# No resources found in test-group-authentication namespace. ## Authentication works!
kubectl get pod --namespace test-user-authentication
# No resources found in test-user-authentication namespace.  ## Authentication works!

kubectl get po --namespace kube-system
# Error from server (Forbidden): pods is forbidden: User "oidc-user:test-user" cannot list resource "pods" in API group "" in the namespace "kube-system"

## As you see, ${OIDC_USER} could not get resources on kube-system but only on test-group-authentication and test-user-authentication namespaces.
```

<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147848335-a6e9d98a-99fe-4669-8759-5fdaffd5698c.gif">
</p>


- This is the end of the OIDC integration of Kubernetes. Next is integrating Keycloak with LDAP to authenticate Kubernetes Cluster.

## LDAP Authentication with Keycloak(as OIDC Provider) 
We have configured our kube-apiserver and Keycloak. Now we can integrate an example LDAP Server with Keycloak to authenticate Kubernetes Cluster with LDAP Authentication.

- We will use Free LDAP test server provided by Zflex. Link is here: [ZFLEXLDAP](https://www.zflexldapadministrator.com/index.php/blog/82-free-online-ldap)
- With the credentials and informations given Zflex site, enter the LDAP attributes like in below(Your own LDAP server may differ the attributes entered here)
	- Note that, I had another page that was already entered the information below on the GIF.
	- Also I have placed extra filter as **(?(employeetype=temp))** to decrease the number of users, because this free site allows us to have 25 member at max.
```yaml
## LDAP Attributes
Edit-Mode: READ-ONLY # Since BindDN itself is a read-only user
Vendor: Active Directory
Username-LDAP-attribute: uid
RDN-LDAP-attribute: uid
UUID-LDAP-attribute: uid
User-Object-Classes: inetOrgPerson,organizationalPerson,person,top # Find out from your own LDAP users objectClass attributes
Connection-URL: ldap://www.zflexldap.com:389
Users-DN: ou=users,ou=guests,dc=ZFLEXSOFTWARE,dc=COM
Custom-User-LDAP-Filter: (&(employeetype=temp))
Search-Scope: Subtree # Usually whole users under the subtree would be requested
Bind-Type: simple
Bind-DN: cn=ro_admin,ou=sysadmins,dc=ZFLEXSOFTWARE,dc=COM # Took it from Zflex page
Bind-Credential: zflexpass # Same goes with Bind DN
```
<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147848784-d8cbb91d-d73f-469b-ad4d-fe13e8bee7b9.gif">
</p>

- We will also add **LDAP group mapper** to authorize with LDAP group.
```yaml
## LDAP Mapper Group Attributes
Name: group # Mapper name
Mapper-Type: group-ldap-mapper # Select type as group-ldap-mapper, so that you can map group attributes of a user.
LDAP-Groups-DN: ou=group,ou=guests,DC=ZFLEXSOFTWARE,DC=COM # Filtering groups based on search value
Group-Name-LDAP-Attribute: cn # Deciding which attribute of group object will be known as the name of group in Keycloak
Group-Object-Classes: groupOfNames,top # Find out from your own LDAP groups objectClass attributes
Membership-LDAP-Attribute: member # Find out from your own LDAP groups membership object name attributes to define
Membership-Attribute-Type: DN # Again find out from your own LDAP groups membership object type attributes to define
Membership-User-LDAP-Attribute: uid # In LDAP Attributes for users we said to define users from its UID, so we define as uid
LDAP-Filter: (&(cn=testGROUP)) # We only needed one group, so I have given only our own group name to define
Mode: READ_ONLY # Since BindDN itself is a read-only user
User-Groups-Retrieve-Strategy: LOAD_GROUPS_BY_MEMBER_ATTRIBUTE # Load groups from groups member attribute, you can get group from user's membership attribute also. There is an option to do that.
Member-Of-LDAP-Attribute: memberOf # This option defines users membership attribute.
```
<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147848959-9694f374-65d7-42fe-8cf7-25e3f0a31b94.gif">
</p>

- We can test it like above example. Define the guest1 user and add its password, after that add it as a user in cluster. The procedure is the same as above.
```bash
## Enter OIDC properties here
OIDC_ISSER_URL="https://app.please-open.it/auth/realms/<YOUR-REALM>"
OIDC_TOKEN_ENDPOINT_URL="https://app.please-open.it/auth/realms/<YOUR-REALM>/protocol/openid-connect/token"
OIDC_CLIENT_ID="account"
OIDC_CLIENT_SECRET="<CLIENT SECRET>"
OIDC_USER="<LDAP-USER>"
OIDC_GROUP="<LDAP-GROUP>"
OIDC_PASSWORD="<LDAP-USER-PASSWORD>"

## We will use refresh_token and id_token from this reply.
OIDC_TOKENS=$(
    curl -X POST -s \
        -H "Content-Type:application/x-www-form-urlencoded" \
        -d "scope=openid" \
        -d "grant_type=password" \
        -d "client_id=${OIDC_CLIENT_ID}" \
        -d "client_secret=${OIDC_CLIENT_SECRET}" \
        -d "username=${OIDC_USER}" \
        -d "password=${OIDC_PASSWORD}" \
        "${OIDC_TOKEN_ENDPOINT_URL}"
)

## Define id_token and refresh_token
OIDC_USER_ID_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .id_token)
OIDC_USER_REFRESH_TOKEN=$(echo "${OIDC_TOKENS}" | jq -r .refresh_token)

kubectl config set-credentials "${OIDC_USER}" \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url="${OIDC_ISSER_URL}" \
   --auth-provider-arg=client-id="${OIDC_CLIENT_ID}" \
   --auth-provider-arg=client-secret="${OIDC_CLIENT_SECRET}" \
   --auth-provider-arg=refresh-token="${OIDC_USER_REFRESH_TOKEN}" \
   --auth-provider-arg=id-token="${OIDC_USER_ID_TOKEN}"
   # --auth-provider-arg=idp-certificate-authority=${HOME}/oidc-ca.crt # When you have your own OIDC instance with signed your own CA, use this option to trust the OIDC site

## Create context with the user created
kubectl config set-context "${OIDC_USER}-context" --user="${OIDC_USER}" --cluster=kubernetes

## Create namespaces named as '{OIDC_GROUP}-authentication' and '${OIDC_USER}-authentication' to test authentication with both group and user name based authentication.
kubectl create namespace "${OIDC_GROUP}-authentication"
kubectl create namespace "${OIDC_USER}-authentication"

## Let's give a rolebinding to specifically to user and group to view resources in created namespaces respectively
kubectl create rolebinding "${OIDC_USER}-view"  --clusterrole=view --user="oidc-user:${OIDC_USER}"    --namespace "${OIDC_GROUP}-authentication"
kubectl create rolebinding "${OIDC_GROUP}-view" --clusterrole=view --group="oidc-group:${OIDC_GROUP}" --namespace "${OIDC_USER}-authentication"

## After that you can switch to the ${OIDC_USER}
kubectl config use-context "${OIDC_USER}"-context

## Test getting the pod of '${OIDC_GROUP}-authentication', '${OIDC_USER}-authentication' and 'kube-system' namespace

kubectl get pod --namespace "${OIDC_GROUP}-authentication"
# No resources found in testGROUP-authentication namespace. ## Authentication works!
kubectl get pod --namespace "${OIDC_USER}-authentication"
# No resources found in guest1-authentication namespace.  ## Authentication works!

kubectl get po --namespace kube-system
# Error from server (Forbidden): pods is forbidden: User "oidc-user:guest1" cannot list resource "pods" in API group "" in the namespace "kube-system"

## As you see, ${OIDC_USER} could not get resources on kube-system but only on testGROUP-authentication and guest1-authentication namespace namespaces.
```
<p align="center">
  <img width="1761" height="1238" src="https://user-images.githubusercontent.com/59168275/147849300-ae7bd029-a4f9-4696-acc1-5b926e8edc2e.gif">
</p>

- Final step is to have Authentication with GUI. We will use Openshift Origin Console for this.

## Kubernetes GUI + LDAP Authentication with Keycloak(as OIDC Provider)
This will be pretty straightforward task. But there is a problem with console. Users must have access to list all namespaces, because it can not list the namespaces in console otherwise. Openshift has **project** object for it, so it can do it without it.
```bash
## Create a ClusterRole for listing namespace
kubectl create clusterrole list-namespace --verb=list --resource=namespace
## And create ClusterRoleBinding for the ${OIDC_GROUP} group to list namespaces
kubectl create clusterrolebinding list-namespace-${OIDC_GROUP} --clusterrole=list-namespace --group="oidc-group:${OIDC_GROUP}"
```
- You will edit'**origin-console.yaml**' file with with what is needed. It is pretty easy to do. Here is an example below.
```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: origin-console-app
  name: origin-console-deployment
  namespace: origin-console
spec:
  selector:
    matchLabels:
      app: origin-console-app
  replicas: 1
  template:
    metadata:
      labels:
        app: origin-console-app
    spec:
      containers:
      - image: quay.io/openshift/origin-console:latest
        name: origin-console-container
        resources:
          requests:
            cpu: 10m
            memory: 100Mi
          limits:
            cpu: 20m
            memory: 200Mi
        command:
          - '/opt/bridge/bin/bridge'
          - '-base-address=https://<KATACODA-PORT-30000-OR-INGRESS-URL>/'
          - '-k8s-mode=in-cluster'
          - '-k8s-auth=oidc'
          - '-listen=http://0.0.0.0:8080'
          - '-public-dir=/opt/bridge/static'
          - '-user-auth=oidc'
          - '-user-auth-oidc-client-id=account'
          - '-user-auth-oidc-issuer-url=https://app.please-open.it/auth/realms/<YOUR-REALM>'
          - '-user-auth-oidc-client-secret=<CLIENT SECRET>'
        ports:
          - name: http
            containerPort: 8080
            protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: origin-console-service
  namespace: origin-console
spec:
  type: NodePort
  selector:
    app: origin-console-app
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 8080
      nodePort: 30000
```
- I have used it to deploy on Katacoda environment, and you can see the test below.
```bash
kubectl create ns origin-console
kubectl create -f origin-console.yaml
```
<p align="center">
  <img width="1934" height="1541" src="https://user-images.githubusercontent.com/59168275/147852146-91231bb4-d5c4-42e9-ad18-0d9c51437410.gif">
</p>

References:
1. https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuring-the-api-server (Kubernetes-OIDC Integration)
2. https://www.janua.fr/ldap-integration-with-keycloak/ (Keycloak-LDAP Integration)
3. https://www.zflexldapadministrator.com/index.php/blog/82-free-online-ldap (Free LDAP Test Server)
