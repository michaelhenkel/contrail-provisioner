module github.com/michaelhenkel/contrail-provisioner

go 1.13

replace (
	github.com/Juniper/contrail-go-api => ../../Juniper/contrail-go-api
	github.com/Juniper/contrail-go-api/types => ../../Juniper/contrail-go-api/types
)

require (
	github.com/Juniper/contrail-go-api v1.1.0
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32 // indirect
	github.com/radovskyb/watcher v1.0.7 // indirect
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413 // indirect
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553 // indirect
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/yaml.v2 v2.2.4
	k8s.io/api v0.17.0 // indirect
	k8s.io/client-go v11.0.0+incompatible // indirect
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
)
