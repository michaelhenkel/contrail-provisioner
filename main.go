package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"

	contrail "github.com/Juniper/contrail-go-api"
	contrailTypes "github.com/Juniper/contrail-go-api/types"
)

// ProvisionConfig defines the structure of the provison config
type ProvisionConfig struct {
	Nodes        *Nodes        `yaml:"nodes,omitempty"`
	GlobalConfig *GlobalConfig `yaml:"globalConfig,omitempty"`
	APIServer    *APIServer    `yaml:"apiServer,omitempty"`
}

type GlobalConfig struct {
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

func nodeManager(nodesPtr *string, nodeType string, contrailClient *contrail.Client) {
	fmt.Printf("%s %s updated\n", nodeType, *nodesPtr)
	nodeYaml, err := ioutil.ReadFile(*nodesPtr)
	if err != nil {
		panic(err)
	}
	switch nodeType {
	case "control":
		var nodeList []*ControlNode
		err = yaml.Unmarshal(nodeYaml, &nodeList)
		if err != nil {
			panic(err)
		}
		if err = controlNodes(contrailClient, nodeList); err != nil {
			panic(err)
		}
	case "analytics":
		var nodeList []*AnalyticsNode
		err = yaml.Unmarshal(nodeYaml, &nodeList)
		if err != nil {
			panic(err)
		}
		if err = analyticsNodes(contrailClient, nodeList); err != nil {
			panic(err)
		}
	case "config":
		var nodeList []*ConfigNode
		err = yaml.Unmarshal(nodeYaml, &nodeList)
		if err != nil {
			panic(err)
		}
		if err = configNodes(contrailClient, nodeList); err != nil {
			panic(err)
		}
	case "vrouter":
		var nodeList []*VrouterNode
		err = yaml.Unmarshal(nodeYaml, &nodeList)
		if err != nil {
			panic(err)
		}
		if err = vrouterNodes(contrailClient, nodeList); err != nil {
			panic(err)
		}
	}
}

func globalConfigManager(globalConfigPtr *string, contrailClient *contrail.Client) {

}

func check(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
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
	globalConfigPtr := flag.String("globalconfig", "/globalconfig.yaml", "path to globalconfig yaml file")
	directoryPtr := flag.String("dir", "/config", "path to watch for config files")
	fmt.Println(*directoryPtr)
	modePtr := flag.String("mode", "watch", "watch/run")
	flag.Parse()
	//controlNodesTarget, err := filepath.EvalSymlinks(*controlNodesPtr)
	//if err != nil {
	//	panic(err)
	//}
	if *modePtr == "watch" {

		var apiServer APIServer
		apiServerYaml, err := ioutil.ReadFile(*apiserverPtr)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(apiServerYaml, &apiServer)
		if err != nil {
			panic(err)
		}

		var contrailClient *contrail.Client
		err = retry(5, 10*time.Second, func() (err error) {
			contrailClient, err = getAPIClient(&apiServer)
			return
		})
		if err != nil {
			if !connectionError(err) {
				panic(err)
			}
		}

		fmt.Println("start watcher")
		done := make(chan bool)

		if globalConfigPtr != nil {
			fmt.Println("intial global config run")
			_, err := os.Stat(*globalConfigPtr)
			if !os.IsNotExist(err) {
				globalConfigManager(controlNodesPtr, contrailClient)
			} else if os.IsNotExist(err) {
				globalConfig(contrailClient, &GlobalConfig{})
			}
			fmt.Println("setting up global config watcher")
			watchFile := strings.Split(*globalConfigPtr, "/")
			watchPath := strings.TrimSuffix(*globalConfigPtr, watchFile[len(watchFile)-1])
			nodeWatcher, err := WatchFile(watchPath, time.Second, func() {
				fmt.Println("global config event")
				_, err := os.Stat(*globalConfigPtr)
				if !os.IsNotExist(err) {
					globalConfigManager(controlNodesPtr, contrailClient)
				} else if os.IsNotExist(err) {
					globalConfig(contrailClient, &GlobalConfig{})
				}
			})
			check(err)

			defer func() {
				nodeWatcher.Close()
			}()
		}

		if controlNodesPtr != nil {
			fmt.Println("intial control node run")
			_, err := os.Stat(*controlNodesPtr)
			if !os.IsNotExist(err) {
				nodeManager(controlNodesPtr, "control", contrailClient)
			} else if os.IsNotExist(err) {
				controlNodes(contrailClient, []*ControlNode{})
			}
			fmt.Println("setting up control node watcher")
			watchFile := strings.Split(*controlNodesPtr, "/")
			watchPath := strings.TrimSuffix(*controlNodesPtr, watchFile[len(watchFile)-1])
			nodeWatcher, err := WatchFile(watchPath, time.Second, func() {
				fmt.Println("control node event")
				_, err := os.Stat(*controlNodesPtr)
				if !os.IsNotExist(err) {
					nodeManager(controlNodesPtr, "control", contrailClient)
				} else if os.IsNotExist(err) {
					controlNodes(contrailClient, []*ControlNode{})
				}
			})
			check(err)

			defer func() {
				nodeWatcher.Close()
			}()
		}

		if vrouterNodesPtr != nil {
			fmt.Println("intial vrouter node run")
			_, err := os.Stat(*vrouterNodesPtr)
			if !os.IsNotExist(err) {
				nodeManager(vrouterNodesPtr, "vrouter", contrailClient)
			} else if os.IsNotExist(err) {
				vrouterNodes(contrailClient, []*VrouterNode{})
			}
			fmt.Println("setting up vrouter node watcher")
			watchFile := strings.Split(*vrouterNodesPtr, "/")
			watchPath := strings.TrimSuffix(*vrouterNodesPtr, watchFile[len(watchFile)-1])
			nodeWatcher, err := WatchFile(watchPath, time.Second, func() {
				fmt.Println("vrouter node event")
				_, err := os.Stat(*vrouterNodesPtr)
				if !os.IsNotExist(err) {
					nodeManager(vrouterNodesPtr, "vrouter", contrailClient)
				} else if os.IsNotExist(err) {
					vrouterNodes(contrailClient, []*VrouterNode{})
				}
			})
			check(err)

			defer func() {
				nodeWatcher.Close()
			}()
		}

		if analyticsNodesPtr != nil {
			fmt.Println("intial analytics node run")
			_, err := os.Stat(*analyticsNodesPtr)
			if !os.IsNotExist(err) {
				nodeManager(analyticsNodesPtr, "analytics", contrailClient)
			} else if os.IsNotExist(err) {
				analyticsNodes(contrailClient, []*AnalyticsNode{})
			}
			fmt.Println("setting up analytics node watcher")
			watchFile := strings.Split(*analyticsNodesPtr, "/")
			watchPath := strings.TrimSuffix(*analyticsNodesPtr, watchFile[len(watchFile)-1])
			nodeWatcher, err := WatchFile(watchPath, time.Second, func() {
				fmt.Println("analytics node event")
				_, err := os.Stat(*analyticsNodesPtr)
				if !os.IsNotExist(err) {
					nodeManager(analyticsNodesPtr, "analytics", contrailClient)
				} else if os.IsNotExist(err) {
					analyticsNodes(contrailClient, []*AnalyticsNode{})
				}
			})
			check(err)

			defer func() {
				nodeWatcher.Close()
			}()
		}

		if configNodesPtr != nil {
			fmt.Println("intial config node run")
			_, err := os.Stat(*configNodesPtr)
			if !os.IsNotExist(err) {
				nodeManager(configNodesPtr, "config", contrailClient)
			} else if os.IsNotExist(err) {
				configNodes(contrailClient, []*ConfigNode{})
			}
			fmt.Println("setting up config node watcher")
			watchFile := strings.Split(*configNodesPtr, "/")
			watchPath := strings.TrimSuffix(*configNodesPtr, watchFile[len(watchFile)-1])
			nodeWatcher, err := WatchFile(watchPath, time.Second, func() {
				fmt.Println("config node event")
				_, err := os.Stat(*configNodesPtr)
				if !os.IsNotExist(err) {
					nodeManager(configNodesPtr, "config", contrailClient)
				} else if os.IsNotExist(err) {
					configNodes(contrailClient, []*ConfigNode{})
				}
			})
			check(err)

			defer func() {
				nodeWatcher.Close()
			}()
		}
		<-done
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
			/*
				if err = controlNodes(contrailClient, controlNodeList); err != nil {
					panic(err)
				}
			*/
			err = retry(5, 10*time.Second, func() (err error) {
				err = controlNodes(contrailClient, controlNodeList)
				return
			})
			if err != nil {
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
func retry(attempts int, sleep time.Duration, f func() error) (err error) {
	for i := 0; ; i++ {
		err = f()
		if err == nil {
			return
		}
		if attempts != 0 {
			if i >= (attempts - 1) {
				break
			}
		}

		time.Sleep(sleep)

		fmt.Println("retrying after error:", err)
	}
	return err
}

func connectionError(err error) bool {
	if err == nil {
		fmt.Println("Ok")
		return false

	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		fmt.Println("Timeout")
		return true
	}
	unwrappedError := errors.Unwrap(err)
	switch t := unwrappedError.(type) {
	case *net.OpError:
		if t.Op == "dial" {
			fmt.Println("Unknown host")
			return true
		} else if t.Op == "read" {
			fmt.Println("Connection refused")
			return true
		}

	case syscall.Errno:
		if t == syscall.ECONNREFUSED {
			fmt.Println("Connection refused")
			return true
		}

	default:
		fmt.Println(t)
	}
	return false
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
	/*apiPortInt, err := strconv.Atoi(apiServerObj.APIPort)
	if err != nil {
		return contrailClient, err
	}
	*/
	for _, apiServer := range apiServerObj.APIServerList {
		apiServerSlice := strings.Split(apiServer, ":")
		apiPortInt, err := strconv.Atoi(apiServerSlice[1])
		if err != nil {
			return contrailClient, err
		}
		fmt.Printf("api server %s:%d\n", apiServerSlice[0], apiPortInt)
		contrailClient := contrail.NewClient(apiServerSlice[0], apiPortInt)
		contrailClient.AddEncryption(apiServerObj.Encryption.CA, apiServerObj.Encryption.Key, apiServerObj.Encryption.Cert, true)
		contrailClient.AddHTTPParameter(1)
		_, err = contrailClient.List("global-system-config")
		if err == nil {
			return contrailClient, nil
		}
	}
	/*
		if connectionError(err) {
			return contrailClient, err
		}
	*/
	return contrailClient, fmt.Errorf("%s", "cannot get api server")

}

func globalConfig(contrailClient *contrail.Client, config *GlobalConfig) error {
	return nil
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
			vncNode.SetName(nodeName)
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

			routingInstance := &contrailTypes.RoutingInstance{}
			routingInstanceObjectsList, err := contrailClient.List("routing-instance")
			if err != nil {
				return err
			}

			if len(routingInstanceObjectsList) == 0 {
				fmt.Println("no routingInstance objects")
			}

			for _, routingInstanceObject := range routingInstanceObjectsList {
				obj, err := contrailClient.ReadListResult("routing-instance", &routingInstanceObject)
				if err != nil {
					return err
				}
				if reflect.DeepEqual(obj.GetFQName(), []string{"default-domain", "default-project", "ip-fabric", "__default__"}) {
					routingInstance = obj.(*contrailTypes.RoutingInstance)
				}
			}

			if routingInstance != nil {
				vncNode.SetParent(routingInstance)
			}

			err = contrailClient.Create(vncNode)
			if err != nil {
				return err
			}

			gscObjects := []*contrailTypes.GlobalSystemConfig{}
			gscObjectsList, err := contrailClient.List("global-system-config")
			if err != nil {
				return err
			}

			if len(gscObjectsList) == 0 {
				fmt.Println("no gscObject")
			}

			for _, gscObject := range gscObjectsList {
				obj, err := contrailClient.ReadListResult("global-system-config", &gscObject)
				if err != nil {
					return err
				}
				gscObjects = append(gscObjects, obj.(*contrailTypes.GlobalSystemConfig))
			}

			if len(gscObjects) > 0 {
				for _, gsc := range gscObjects {
					if err := gsc.AddBgpRouter(vncNode); err != nil {
						return err
					}
					if err := contrailClient.Update(gsc); err != nil {
						return err
					}
				}
			}

		}
	}

	gscObjects := []*contrailTypes.GlobalSystemConfig{}
	gscObjectsList, err := contrailClient.List("global-system-config")
	if err != nil {
		return err
	}

	if len(gscObjectsList) == 0 {
		fmt.Println("no gscObject")
	}

	for _, gscObject := range gscObjectsList {
		obj, err := contrailClient.ReadListResult("global-system-config", &gscObject)
		if err != nil {
			return err
		}
		gscObjects = append(gscObjects, obj.(*contrailTypes.GlobalSystemConfig))
	}

	if len(gscObjects) > 0 {
		for _, gsc := range gscObjects {
			bgpRefs, err := gsc.GetBgpRouterRefs()
			if err != nil {
				return err
			}
			for _, bgpRef := range bgpRefs {
				fmt.Println(bgpRef)
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
			gscObjects := []*contrailTypes.GlobalSystemConfig{}
			gscObjectsList, err := contrailClient.List("global-system-config")
			if err != nil {
				return err
			}

			if len(gscObjectsList) == 0 {
				fmt.Println("no gscObject")
			}

			for _, gscObject := range gscObjectsList {
				obj, err := contrailClient.ReadListResult("global-system-config", &gscObject)
				if err != nil {
					return err
				}
				gscObjects = append(gscObjects, obj.(*contrailTypes.GlobalSystemConfig))
			}

			if len(gscObjects) > 0 {
				for _, gsc := range gscObjects {
					if err := gsc.DeleteBgpRouter(obj.GetUuid()); err != nil {
						return err
					}
					if err := contrailClient.Update(gsc); err != nil {
						return err
					}
				}
			}
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
			vncNode.SetFQName("", []string{"default-global-system-config", nodeName})
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
					typedNode.SetFQName("", []string{"default-global-system-config", nodeName})
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
			node := &VrouterNode{}
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
			gscObjects := []*contrailTypes.GlobalSystemConfig{}
			gscObjectsList, err := contrailClient.List("global-system-config")
			if err != nil {
				return err
			}

			if len(gscObjectsList) == 0 {
				fmt.Println("no gscObject")
			}

			for _, gscObject := range gscObjectsList {
				obj, err := contrailClient.ReadListResult("global-system-config", &gscObject)
				if err != nil {
					return err
				}
				gscObjects = append(gscObjects, obj.(*contrailTypes.GlobalSystemConfig))
			}
			gscObject := &contrailTypes.GlobalSystemConfig{}
			if len(gscObjects) > 0 {
				for _, gsc := range gscObjects {
					gscObject = gsc
					vncNode := &contrailTypes.VirtualRouter{}
					vncNode.SetFQName("", []string{"default-global-system-config", nodeName})
					vncNode.SetVirtualRouterIpAddress(node.IPAddress)
					vncNode.SetParent(gscObject)
					err := contrailClient.Create(vncNode)
					if err != nil {
						return err
					}
					return nil
				}
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
