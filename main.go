package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/radovskyb/watcher"
	"gopkg.in/yaml.v2"

	contrail "github.com/Juniper/contrail-go-api"
	contrailTypes "github.com/Juniper/contrail-go-api/types"
)

// ProvisionConfig defines the structure of the provison config
type ProvisionConfig struct {
	Nodes     *Nodes     `yaml:"nodes,omitempty"`
	APIServer *APIServer `yaml:"apiServer,omitempty"`
}

type Nodes struct {
	ControlNodes   []*ControlNode             `yaml:"controlNodes,omitempty"`
	BgpRouters     []*contrailTypes.BgpRouter `yaml:"bgpRouters,omitempty"`
	AnalyticsNodes []*AnalyticsNode           `yaml:"analyticsNodes,omitempty"`
	VrouterNodes   []*VrouterNode             `yaml:"vrouterNodes,omitempty"`
	ConfigNodes    []*ConfigNode              `yaml:"configNodes,omitempty"`
}

type APIServer struct {
	APIPort       string     `yaml:"apiPort,omitempty"`
	APIServerList []string   `yaml:"apiServerList,omitempty"`
	Encryption    encryption `yaml:"encryption,omitempty"`
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
	controlNodesPtr := flag.String("controlNodes", "/provision.yaml", "path to control nodes yaml file")
	configNodesPtr := flag.String("configNodes", "/provision.yaml", "path to config nodes yaml file")
	analyticsNodesPtr := flag.String("analyticsNodes", "/provision.yaml", "path to analytics nodes yaml file")
	vrouterNodesPtr := flag.String("vrouterNodes", "/provision.yaml", "path to vrouter nodes yaml file")
	apiserverPtr := flag.String("apiserver", "/provision.yaml", "path to apiserver yaml file")
	directoryPtr := flag.String("dir", "/config", "path to watch for config files")
	modePtr := flag.String("mode", "watch", "watch/run")
	flag.Parse()
	if *modePtr == "watch" {
		w := watcher.New()
		w.SetMaxEvents(2)
		//w.FilterOps(watcher.Write, watcher.Create)
		go func() {
			for {
				select {
				case event := <-w.Event:
					fmt.Println(event)
					if !event.IsDir() && (event.Op.String() == "WRITE" || event.Op.String() == "CREATE" || event.Op.String() == "RENAME") {
						//fmt.Println(event.Path + "/" + event.FileInfo.Name()) // Print the event's info.
						//fmt.Println(event.Op)
						var apiServer APIServer
						apiServerYaml, err := ioutil.ReadFile(*apiserverPtr)
						if err != nil {
							panic(err)
						}
						err = yaml.Unmarshal(apiServerYaml, &apiServer)
						if err != nil {
							panic(err)
						}
						contrailClient, err := getAPIClient(&apiServer)
						if err != nil {
							panic(err.Error())
						}

						if controlNodesPtr != nil {
							fileInfo, err := os.Stat(*controlNodesPtr)
							if !os.IsNotExist(err) {
								if event.Name() == fileInfo.Name() {
									var controlNodeList []*ControlNode
									controlNodeYaml, err := ioutil.ReadFile(*controlNodesPtr)
									if err != nil {
										panic(err)
									}
									err = yaml.Unmarshal(controlNodeYaml, &controlNodeList)
									if err != nil {
										panic(err)
									}
									if err = controlNodes(contrailClient, controlNodeList); err != nil {
										panic(err)
									}
								}
							}
						}

						if configNodesPtr != nil {
							fileInfo, err := os.Stat(*configNodesPtr)
							if !os.IsNotExist(err) {
								if event.Name() == fileInfo.Name() {
									var configNodeList []*ConfigNode
									configNodeYaml, err := ioutil.ReadFile(*configNodesPtr)
									if err != nil {
										panic(err)
									}
									err = yaml.Unmarshal(configNodeYaml, &configNodeList)
									if err != nil {
										panic(err)
									}
									if err = configNodes(contrailClient, configNodeList); err != nil {
										panic(err)
									}
								}
							}
						}

						if analyticsNodesPtr != nil {
							fileInfo, err := os.Stat(*analyticsNodesPtr)
							if !os.IsNotExist(err) {
								if event.Name() == fileInfo.Name() {
									var analyticsNodeList []*AnalyticsNode
									analyticsNodeYaml, err := ioutil.ReadFile(*analyticsNodesPtr)
									if err != nil {
										panic(err)
									}
									err = yaml.Unmarshal(analyticsNodeYaml, &analyticsNodeList)
									if err != nil {
										panic(err)
									}
									if err = analyticsNodes(contrailClient, analyticsNodeList); err != nil {
										panic(err)
									}
								}
							}
						}

						if vrouterNodesPtr != nil {
							fileInfo, err := os.Stat(*vrouterNodesPtr)
							if !os.IsNotExist(err) {
								if event.Name() == fileInfo.Name() {
									var vrouterNodeList []*VrouterNode
									vrouterNodeYaml, err := ioutil.ReadFile(*vrouterNodesPtr)
									if err != nil {
										panic(err)
									}
									err = yaml.Unmarshal(vrouterNodeYaml, &vrouterNodeList)
									if err != nil {
										panic(err)
									}
									if err = vrouterNodes(contrailClient, vrouterNodeList); err != nil {
										panic(err)
									}
								}
							}
						}
					}
				case err := <-w.Error:
					panic(err)
				case <-w.Closed:
					return
				}
			}
		}()
		if err := w.Add(*directoryPtr); err != nil {
			panic(err)
		}
		for path, f := range w.WatchedFiles() {
			fmt.Printf("%s: %s\n", path, f.Name())
		}
		fmt.Println()
		go func() {
			w.Wait()
			if controlNodesPtr != nil {
				fileInfo, err := os.Stat(*controlNodesPtr)
				if !os.IsNotExist(err) {
					w.TriggerEvent(watcher.Write, fileInfo)
				}
			}
			if configNodesPtr != nil {
				fileInfo, err := os.Stat(*configNodesPtr)
				if !os.IsNotExist(err) {
					w.TriggerEvent(watcher.Write, fileInfo)
				}
			}
			if analyticsNodesPtr != nil {
				fileInfo, err := os.Stat(*analyticsNodesPtr)
				if !os.IsNotExist(err) {
					w.TriggerEvent(watcher.Write, fileInfo)
				}
			}
			if vrouterNodesPtr != nil {
				fileInfo, err := os.Stat(*vrouterNodesPtr)
				if !os.IsNotExist(err) {
					w.TriggerEvent(watcher.Write, fileInfo)
				}
			}
		}()
		if err := w.Start(time.Millisecond * 100); err != nil {
			panic(err)
		}
	}

	if *modePtr == "run" {

		var apiServer APIServer

		apiServerYaml, err := ioutil.ReadFile(*apiserverPtr)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(apiServerYaml, &apiServer)
		if err != nil {
			panic(err)
		}
		contrailClient, err := getAPIClient(&apiServer)
		if err != nil {
			panic(err.Error())
		}

		if controlNodesPtr != nil {
			var controlNodeList []*ControlNode
			controlNodeYaml, err := ioutil.ReadFile(*controlNodesPtr)
			if err != nil {
				panic(err)
			}
			err = yaml.Unmarshal(controlNodeYaml, &controlNodeList)
			if err != nil {
				panic(err)
			}
			if err = controlNodes(contrailClient, controlNodeList); err != nil {
				panic(err)
			}
		}

		if configNodesPtr != nil {
			var configNodeList []*ConfigNode
			configNodeYaml, err := ioutil.ReadFile(*configNodesPtr)
			if err != nil {
				panic(err)
			}
			err = yaml.Unmarshal(configNodeYaml, &configNodeList)
			if err != nil {
				panic(err)
			}
			if err = configNodes(contrailClient, configNodeList); err != nil {
				panic(err)
			}
		}

		if analyticsNodesPtr != nil {
			var analyticsNodeList []*AnalyticsNode
			analyticsNodeYaml, err := ioutil.ReadFile(*analyticsNodesPtr)
			if err != nil {
				panic(err)
			}
			err = yaml.Unmarshal(analyticsNodeYaml, &analyticsNodeList)
			if err != nil {
				panic(err)
			}
			if err = analyticsNodes(contrailClient, analyticsNodeList); err != nil {
				panic(err)
			}
		}

		if vrouterNodesPtr != nil {
			var vrouterNodeList []*VrouterNode
			vrouterNodeYaml, err := ioutil.ReadFile(*vrouterNodesPtr)
			if err != nil {
				panic(err)
			}
			err = yaml.Unmarshal(vrouterNodeYaml, &vrouterNodeList)
			if err != nil {
				panic(err)
			}
			if err = vrouterNodes(contrailClient, vrouterNodeList); err != nil {
				panic(err)
			}
		}

	}
}

func checkErr(err error) {
	if err == nil {
		fmt.Println("Ok")
		return

	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		fmt.Println("Timeout")
		return
	}

	switch t := err.(type) {
	case *net.OpError:
		if t.Op == "dial" {
			fmt.Println("Unknown host")
		} else if t.Op == "read" {
			fmt.Println("Connection refused")
		}

	case syscall.Errno:
		if t == syscall.ECONNREFUSED {
			fmt.Println("Connection refused")
		}

	default:
		fmt.Println(t)
	}

}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func getAPIClient(apiServerObj *APIServer) (*contrail.Client, error) {
	var contrailClient *contrail.Client
	apiPortInt, err := strconv.Atoi(apiServerObj.APIPort)
	if err != nil {
		return contrailClient, err
	}
	for _, apiServer := range apiServerObj.APIServerList {
		contrailClient := contrail.NewClient(apiServer, apiPortInt)
		contrailClient.AddEncryption(apiServerObj.Encryption.CA, apiServerObj.Encryption.Key, apiServerObj.Encryption.Cert, true)
		_, err = contrailClient.List("test")
		if err != nil {
			checkErr(err)
		} else {
			return contrailClient, nil
		}
	}
	return contrailClient, nil

}

func controlNodes(contrailClient *contrail.Client, nodeList []*ControlNode) error {
	var actionMap = make(map[string]string)
	//Get all control nodes from configDB
	nodeType := "bgp-router"
	vncNodes := []*ControlNode{}
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
		vncNodes = append(vncNodes, node)
	}
	for _, node := range nodeList {
		actionMap[node.Hostname] = "create"
	}
	for _, vncNode := range vncNodes {
		if _, ok := actionMap[vncNode.Hostname]; ok {
			for _, node := range nodeList {
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
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("updating node ", node.Hostname)
					//err = updateNode(provisionConfig, nodeType, k, contrailClient)
					err = node.Update(nodeList, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "create":
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("creating node ", node.Hostname)
					//err = createNode(provisionConfig, nodeType, k, contrailClient)
					err = node.Create(nodeList, node.Hostname, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "delete":
			node := &ControlNode{}
			err = node.Delete(k, contrailClient)
			if err != nil {
				return err
			}
			fmt.Println("deleting node ", k)
		}
	}
	return nil
}

func (c *ControlNode) Create(nodeList []*ControlNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
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
	return nil
}

func (c *ControlNode) Update(nodeList []*ControlNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNodeList, err := contrailClient.List("bgp-router")
			if err != nil {
				return err
			}
			for _, vncNode := range vncNodeList {
				obj, err := contrailClient.ReadListResult("bgp-router", &vncNode)
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
	return nil
}

func (c *ControlNode) Delete(nodeName string, contrailClient *contrail.Client) error {
	vncNodeList, err := contrailClient.List("bgp-router")
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult("bgp-router", &vncNode)
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
	return nil
}

func configNodes(contrailClient *contrail.Client, nodeList []*ConfigNode) error {
	var actionMap = make(map[string]string)
	//Get all control nodes from configDB
	nodeType := "config-node"
	vncNodes := []*ConfigNode{}
	vncNodeList, err := contrailClient.List(nodeType)
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
		if err != nil {
			return err
		}
		typedNode := obj.(*contrailTypes.ConfigNode)

		node := &ConfigNode{
			IPAddress: typedNode.GetConfigNodeIpAddress(),
			Hostname:  typedNode.GetName(),
		}
		vncNodes = append(vncNodes, node)
	}
	for _, node := range nodeList {
		actionMap[node.Hostname] = "create"
	}
	for _, vncNode := range vncNodes {
		if _, ok := actionMap[vncNode.Hostname]; ok {
			for _, node := range nodeList {
				if node.Hostname == vncNode.Hostname {
					actionMap[node.Hostname] = "noop"
					if node.IPAddress != vncNode.IPAddress {
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
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("updating node ", node.Hostname)
					err = node.Update(nodeList, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "create":
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("creating node ", node.Hostname)
					err = node.Create(nodeList, node.Hostname, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "delete":
			node := &ConfigNode{}
			err = node.Delete(k, contrailClient)
			if err != nil {
				return err
			}
			fmt.Println("deleting node ", k)
		}
	}
	return nil
}

func (c *ConfigNode) Create(nodeList []*ConfigNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNode := &contrailTypes.ConfigNode{}
			vncNode.SetFQName("", []string{"default-global-system-config", nodeName})
			vncNode.SetConfigNodeIpAddress(node.IPAddress)
			err := contrailClient.Create(vncNode)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *ConfigNode) Update(nodeList []*ConfigNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNodeList, err := contrailClient.List("config-node")
			if err != nil {
				return err
			}
			for _, vncNode := range vncNodeList {
				obj, err := contrailClient.ReadListResult("config-node", &vncNode)
				if err != nil {
					return err
				}
				typedNode := obj.(*contrailTypes.ConfigNode)
				if typedNode.GetName() == nodeName {
					typedNode.SetFQName("", []string{"default-global-system-config", nodeName})
					typedNode.SetConfigNodeIpAddress(node.IPAddress)
					err := contrailClient.Update(typedNode)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (c *ConfigNode) Delete(nodeName string, contrailClient *contrail.Client) error {
	vncNodeList, err := contrailClient.List("config-node")
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult("config-node", &vncNode)
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
	return nil
}

func analyticsNodes(contrailClient *contrail.Client, nodeList []*AnalyticsNode) error {
	var actionMap = make(map[string]string)
	//Get all control nodes from configDB
	nodeType := "analytics-node"
	vncNodes := []*AnalyticsNode{}
	vncNodeList, err := contrailClient.List(nodeType)
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
		if err != nil {
			return err
		}
		typedNode := obj.(*contrailTypes.AnalyticsNode)

		node := &AnalyticsNode{
			IPAddress: typedNode.GetAnalyticsNodeIpAddress(),
			Hostname:  typedNode.GetName(),
		}
		vncNodes = append(vncNodes, node)
	}
	for _, node := range nodeList {
		actionMap[node.Hostname] = "create"
	}
	for _, vncNode := range vncNodes {
		if _, ok := actionMap[vncNode.Hostname]; ok {
			for _, node := range nodeList {
				if node.Hostname == vncNode.Hostname {
					actionMap[node.Hostname] = "noop"
					if node.IPAddress != vncNode.IPAddress {
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
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("updating node ", node.Hostname)
					err = node.Update(nodeList, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "create":
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("creating node ", node.Hostname)
					err = node.Create(nodeList, node.Hostname, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "delete":
			node := &ConfigNode{}
			err = node.Delete(k, contrailClient)
			if err != nil {
				return err
			}
			fmt.Println("deleting node ", k)
		}
	}
	return nil
}

func (c *AnalyticsNode) Create(nodeList []*AnalyticsNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNode := &contrailTypes.AnalyticsNode{}
			vncNode.SetFQName("", []string{"default-domain", "default-project", "ip-fabric", "__default__", nodeName})
			vncNode.SetAnalyticsNodeIpAddress(node.IPAddress)
			err := contrailClient.Create(vncNode)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *AnalyticsNode) Update(nodeList []*AnalyticsNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNodeList, err := contrailClient.List("analytics-node")
			if err != nil {
				return err
			}
			for _, vncNode := range vncNodeList {
				obj, err := contrailClient.ReadListResult("analytics-node", &vncNode)
				if err != nil {
					return err
				}
				typedNode := obj.(*contrailTypes.AnalyticsNode)
				if typedNode.GetName() == nodeName {
					typedNode.SetFQName("", []string{"default-domain", "default-project", "ip-fabric", "__default__", nodeName})
					typedNode.SetAnalyticsNodeIpAddress(node.IPAddress)
					err := contrailClient.Update(typedNode)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (c *AnalyticsNode) Delete(nodeName string, contrailClient *contrail.Client) error {
	vncNodeList, err := contrailClient.List("analytics-node")
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult("analytics-node", &vncNode)
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
	return nil
}

func vrouterNodes(contrailClient *contrail.Client, nodeList []*VrouterNode) error {
	var actionMap = make(map[string]string)
	//Get all control nodes from configDB
	nodeType := "virtual-router"
	vncNodes := []*VrouterNode{}
	vncNodeList, err := contrailClient.List(nodeType)
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult(nodeType, &vncNode)
		if err != nil {
			return err
		}
		typedNode := obj.(*contrailTypes.VirtualRouter)

		node := &VrouterNode{
			IPAddress: typedNode.GetVirtualRouterIpAddress(),
			Hostname:  typedNode.GetName(),
		}
		vncNodes = append(vncNodes, node)
	}
	for _, node := range nodeList {
		actionMap[node.Hostname] = "create"
	}
	for _, vncNode := range vncNodes {
		if _, ok := actionMap[vncNode.Hostname]; ok {
			for _, node := range nodeList {
				if node.Hostname == vncNode.Hostname {
					actionMap[node.Hostname] = "noop"
					if node.IPAddress != vncNode.IPAddress {
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
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("updating node ", node.Hostname)
					err = node.Update(nodeList, k, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "create":
			for _, node := range nodeList {
				if node.Hostname == k {
					fmt.Println("creating node ", node.Hostname)
					err = node.Create(nodeList, node.Hostname, contrailClient)
					if err != nil {
						return err
					}
				}
			}
		case "delete":
			node := &ConfigNode{}
			err = node.Delete(k, contrailClient)
			if err != nil {
				return err
			}
			fmt.Println("deleting node ", k)
		}
	}
	return nil
}

func (c *VrouterNode) Create(nodeList []*VrouterNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNode := &contrailTypes.VirtualRouter{}
			vncNode.SetFQName("", []string{"default-global-system-config", nodeName})
			vncNode.SetVirtualRouterIpAddress(node.IPAddress)
			err := contrailClient.Create(vncNode)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *VrouterNode) Update(nodeList []*VrouterNode, nodeName string, contrailClient *contrail.Client) error {
	for _, node := range nodeList {
		if node.Hostname == nodeName {
			vncNodeList, err := contrailClient.List("virtual-router")
			if err != nil {
				return err
			}
			for _, vncNode := range vncNodeList {
				obj, err := contrailClient.ReadListResult("virtual-router", &vncNode)
				if err != nil {
					return err
				}
				typedNode := obj.(*contrailTypes.VirtualRouter)
				if typedNode.GetName() == nodeName {
					typedNode.SetFQName("", []string{"default-global-system-config", nodeName})
					typedNode.SetVirtualRouterIpAddress(node.IPAddress)
					err := contrailClient.Update(typedNode)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (c *VrouterNode) Delete(nodeName string, contrailClient *contrail.Client) error {
	vncNodeList, err := contrailClient.List("virtual-router")
	if err != nil {
		return err
	}
	for _, vncNode := range vncNodeList {
		obj, err := contrailClient.ReadListResult("virtual-router", &vncNode)
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
	return nil
}
