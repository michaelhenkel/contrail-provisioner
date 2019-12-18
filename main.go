package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"

	"gopkg.in/yaml.v2"

	contrail "github.com/Juniper/contrail-go-api"
	contrailTypes "github.com/Juniper/contrail-go-api/types"
)

// ProvisionConfig defines the structure of the provison config
type ProvisionConfig struct {
	ControlNodes   []*ControlNode             `yaml:"controlNodes,omitempty"`
	BgpRouters     []*contrailTypes.BgpRouter `yaml:"bgpRouters,omitempty"`
	AnalyticsNodes []*AnalyticsNode           `yaml:"analyticsNodes,omitempty"`
	VrouterNodes   []*VrouterNode             `yaml:"vrouterNodes,omitempty"`
	ConfigNodes    []*ConfigNode              `yaml:"configNodes,omitempty"`
	ASN            int                        `yaml:"asn,omitempty"`
	APIPort        string                     `yaml:"apiPort,omitempty"`
	APIServerList  []string                   `yaml:"apiServerList,omitempty"`
	Encryption     encryption                 `yaml:"encryption,omitempty"`
}

type encryption struct {
	CA       string `yaml:"ca,omitempty"`
	Cert     string `yaml:"cert,omitempty"`
	Key      string `yaml:"key,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
}

type ControlNode struct {
	IPAddress string `yaml:"ipAddress,omitempty"`
	Hostname  string `yaml:"hostname,omitempty"`
	ASN       int    `yaml:"asn,omitempty"`
}

type NodeHandler interface {
	Create()
}

type ConfigNode struct {
	IPAddress string `yaml:"ipAddress,omitempty"`
	Hostname  string `yaml:"hostname,omitempty"`
}

type AnalyticsNode struct {
	IPAddress string `yaml:"ipAddress,omitempty"`
	Hostname  string `yaml:"hostname,omitempty"`
}

type VrouterNode struct {
	IPAddress string `yaml:"ipAddress,omitempty"`
	Hostname  string `yaml:"hostname,omitempty"`
}

func main() {
	//if len(os.Args) != 1 {
	//	panic("wrong number of args")
	//}

	filePtr := flag.String("file", "/provision.yaml", "path to provision yaml file")
	flag.Parse()
	configYaml, err := ioutil.ReadFile(*filePtr)
	if err != nil {
		panic(err)
	}
	var config ProvisionConfig
	err = yaml.Unmarshal(configYaml, &config)
	if err != nil {
		panic(err)
	}
	err = provision(&config)
	if err != nil {
		panic(err.Error())
	}
}

func provision(provisionConfig *ProvisionConfig) error {
	apiPortInt, err := strconv.Atoi(provisionConfig.APIPort)
	if err != nil {
		return err
	}
	for _, apiServer := range provisionConfig.APIServerList {
		contrailClient := contrail.NewClient(apiServer, apiPortInt)
		contrailClient.AddEncryption(provisionConfig.Encryption.CA, provisionConfig.Encryption.Key, provisionConfig.Encryption.Cert, true)
		if err = createNodesInConfigDB(contrailClient, provisionConfig); err != nil {
			return err
		}
	}
	return nil

}

func createNodesInConfigDB(contrailClient *contrail.Client, provisionConfig *ProvisionConfig) error {
	//Get all control nodes from configDB
	nodeType := "bgp-router"
	vncControlNodes := []*ControlNode{}
	vncNodeList, err := contrailClient.List(nodeType)
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
		if err != nil {
			return err
		}
		typedNode := obj.(*contrailTypes.BgpRouter)

		bgpRouterParamters := typedNode.GetBgpRouterParameters()
		node := &ControlNode{
			IPAddress: bgpRouterParamters.Address,
			Hostname:  typedNode.GetName(),
			ASN:       bgpRouterParamters.AutonomousSystem,
		}
		vncControlNodes = append(vncControlNodes, node)

	}
	var actionMap = make(map[string]string)
	for _, node := range provisionConfig.ControlNodes {
		actionMap[node.Hostname] = "create"
	}

	for _, vncNode := range vncControlNodes {
		if _, ok := actionMap[vncNode.Hostname]; ok {
			for _, node := range provisionConfig.ControlNodes {
				if node.Hostname == vncNode.Hostname {
					actionMap[node.Hostname] = "noop"
					if node.IPAddress != vncNode.IPAddress {
						actionMap[node.Hostname] = "update"
					}
					if node.ASN != vncNode.ASN {
						actionMap[node.Hostname] = "update"
					}
				}
			}
		} else {
			actionMap[vncNode.Hostname] = "delete"
		}
	}

	for k, v := range actionMap {
		switch v {
		case "update":
			for _, node := range provisionConfig.ControlNodes {
				if node.Hostname == k {
					fmt.Println("updating node ", node.Hostname)
					err = updateNode(provisionConfig, nodeType, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "create":
			for _, node := range provisionConfig.ControlNodes {
				if node.Hostname == k {
					fmt.Println("creating node ", node.Hostname)
					err = createNode(provisionConfig, nodeType, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "delete":
			err = deleteNode(nodeType, k, contrailClient)
			if err != nil {
				return err
			}
			fmt.Println("deleting node ", k)
		}
	}

	return nil
}

func createNode(provisionConfig *ProvisionConfig, nodeType string, nodeName string, contrailClient *contrail.Client) error {
	switch nodeType {
	case "bgp-router":
		for _, node := range provisionConfig.ControlNodes {
			if node.Hostname == nodeName {
				vncNode := &contrailTypes.BgpRouter{}
				vncNode.SetFQName("", []string{"default-domain", "default-project", "ip-fabric", "__default__", nodeName})
				bgpParameters := &contrailTypes.BgpRouterParams{
					Address:          node.IPAddress,
					AutonomousSystem: node.ASN,
					Vendor:           "contrail",
					RouterType:       "control-node",
					AdminDown:        false,
					Identifier:       node.IPAddress,
					HoldTime:         90,
					Port:             179,
					AddressFamilies: &contrailTypes.AddressFamilies{
						Family: []string{"route-target", "inet-vpn", "inet6-vpn", "e-vpn", "erm-vpn"},
					},
				}
				vncNode.SetBgpRouterParameters(bgpParameters)
				err := contrailClient.Create(vncNode)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func updateNode(provisionConfig *ProvisionConfig, nodeType string, nodeName string, contrailClient *contrail.Client) error {
	switch nodeType {
	case "bgp-router":
		for _, node := range provisionConfig.ControlNodes {
			if node.Hostname == nodeName {
				vncNodeList, err := contrailClient.List(nodeType)
				if err != nil {
					return err
				}
				for _, vncNode := range vncNodeList {
					obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
					if err != nil {
						return err
					}
					typedNode := obj.(*contrailTypes.BgpRouter)
					if typedNode.GetName() == nodeName {
						typedNode.SetFQName("", []string{"default-domain", "default-project", "ip-fabric", "__default__", nodeName})
						bgpParameters := &contrailTypes.BgpRouterParams{
							Address:          node.IPAddress,
							AutonomousSystem: node.ASN,
							Vendor:           "contrail",
							RouterType:       "control-node",
							AdminDown:        false,
							Identifier:       node.IPAddress,
							HoldTime:         90,
							Port:             179,
							AddressFamilies: &contrailTypes.AddressFamilies{
								Family: []string{"route-target", "inet-vpn", "inet6-vpn", "e-vpn", "erm-vpn"},
							},
						}
						typedNode.SetBgpRouterParameters(bgpParameters)
						err := contrailClient.Update(typedNode)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func deleteNode(nodeType string, nodeName string, contrailClient *contrail.Client) error {
	switch nodeType {
	case "bgp-router":
		vncNodeList, err := contrailClient.List(nodeType)
		if err != nil {
			return err
		}
		for _, vncNode := range vncNodeList {
			obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
			if err != nil {
				return err
			}
			if obj.GetName() == nodeName {
				err = contrailClient.Delete(obj)
				if err != nil {
					return err
				}
			}
		}

	}
	return nil
}
