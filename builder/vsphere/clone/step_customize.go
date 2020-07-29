//go:generate struct-markdown
//go:generate mapstructure-to-hcl2 -type CustomizeConfig,LinuxOptions,NetworkInterfaces,NetworkInterface
package clone

import (
	"context"
	"fmt"
	"github.com/hashicorp/packer/builder/vsphere/driver"
	"github.com/hashicorp/packer/helper/config"
	"github.com/hashicorp/packer/helper/multistep"
	"github.com/hashicorp/packer/packer"
	"github.com/vmware/govmomi/vim25/types"
	"io/ioutil"
	"net"
)


type CustomizeConfig struct {
	// Settings to Linux guest OS customization.
	LinuxOptions *LinuxOptions `mapstructure:"linux_options"`
	// todo
	NetworkInterfaces NetworkInterfaces `mapstructure:"network_interface"`
	// Supply your own sysprep.xml file contents to allow full control of the customization process out-of-band of vSphere.
	WindowsSysPrepFile string `mapstructure:"windows_sysprep_file"`
	Ipv4Gateway string `mapstructure:"ipv4_gateway"`
	Ipv6Gateway string `mapstructure:"ipv6_gateway"`
}

type LinuxOptions struct {
	// The domain name for this machine. This, along with host_name, make up the FQDN of this virtual machine.
	Domain string `mapstructure:"domain"`
	// The host name for this machine. This, along with domain, make up the FQDN of this virtual machine.
	Hostname string `mapstructure:"host_name"`
	// Tells the operating system that the hardware clock is set to UTC. Default: true.
	HWClockUTC config.Trilean `mapstructure:"hw_clock_utc"`
	// Sets the time zone. The default is UTC.
	Timezone string `mapstructure:"time_zone"`
}

type NetworkInterface struct {
	DnsServerList []string `mapstructure:"dns_server_list"`
	DnsDomain     string   `mapstructure:"dns_domain"`
	Ipv4Address   string   `mapstructure:"ipv4_address"`
	Ipv4NetMask   int      `mapstructure:"ipv4_netmask"`
	Ipv6Address   string   `mapstructure:"ipv6_address"`
	Ipv6NetMask   int      `mapstructure:"ipv6_netmask"`
}

type NetworkInterfaces []NetworkInterface

type StepCustomize struct {
	Config *CustomizeConfig
}

func (c *CustomizeConfig) Prepare() []error {
	var errs []error

	if c.LinuxOptions == nil && c.WindowsSysPrepFile == "" {
		errs = append(errs, fmt.Errorf("customize is empty"))
	}
	if c.LinuxOptions != nil && c.WindowsSysPrepFile != "" {
		errs = append(errs, fmt.Errorf("`linux_options` and `windows_sysprep_text` both set - one must not be included if the other is specified"))
	}

	if c.LinuxOptions != nil {
		if c.LinuxOptions.Hostname == "" {
			errs = append(errs, fmt.Errorf("linux options `host_name` is empty"))
		}
		if c.LinuxOptions.Domain == "" {
			errs = append(errs, fmt.Errorf("linux options `domain` is empty"))
		}

		if c.LinuxOptions.HWClockUTC == config.TriUnset {
			c.LinuxOptions.HWClockUTC = config.TriTrue
		}
		if c.LinuxOptions.Timezone == "" {
			c.LinuxOptions.Timezone = "UTC"
		}
	}

	return errs
}

func (s *StepCustomize) Run(_ context.Context, state multistep.StateBag) multistep.StepAction {
	vm := state.Get("vm").(*driver.VirtualMachine)
	ui := state.Get("ui").(packer.Ui)

	identity, err := s.identitySettings()
	if err != nil {
		state.Put("error", err)
		return multistep.ActionHalt
	}

	nicSettingsMap, err := s.nicSettingsMap()
	if err != nil {
		state.Put("error", err)
		return multistep.ActionHalt
	}

	spec := types.CustomizationSpec{
		Identity: identity,
		NicSettingMap: nicSettingsMap,
	}
	ui.Say("Customizing VM...")
	err = vm.Customize(spec)
	if err != nil {
		state.Put("error", err)
		return multistep.ActionHalt
	}

	return multistep.ActionContinue
}

func (s *StepCustomize) identitySettings() (types.BaseCustomizationIdentitySettings, error) {
	if s.Config.LinuxOptions != nil {
		return &types.CustomizationLinuxPrep{
			HostName: &types.CustomizationFixedName{
				Name: s.Config.LinuxOptions.Hostname,
			},
			Domain:     s.Config.LinuxOptions.Domain,
			TimeZone:   s.Config.LinuxOptions.Timezone,
			HwClockUTC: s.Config.LinuxOptions.HWClockUTC.ToBoolPointer(),
		}, nil
	}

	if s.Config.WindowsSysPrepFile != "" {
		sysPrep, err := ioutil.ReadFile(s.Config.WindowsSysPrepFile)
		if err != nil {
			return nil, fmt.Errorf("error on reading %s: %s", s.Config.WindowsSysPrepFile, err)
		}
		return &types.CustomizationSysprepText{
			Value: string(sysPrep),
		}, nil
	}

	return nil, fmt.Errorf("no customization identity found")
}

func (s *StepCustomize) Cleanup(_ multistep.StateBag) {}

func (s *StepCustomize) nicSettingsMap() ([]types.CustomizationAdapterMapping, error) {
	result := make([]types.CustomizationAdapterMapping, len(s.Config.NetworkInterfaces))
	var v4gwFound, v6gwFound bool
	for i := range s.Config.NetworkInterfaces {
		var adapter types.CustomizationIPSettings
		adapter, v4gwFound, v6gwFound = s.ipSettings(i, !v4gwFound, !v6gwFound)
		obj := types.CustomizationAdapterMapping{
			Adapter: adapter,
		}
		result[i] = obj
	}
	return result, nil
}

func (s *StepCustomize) ipSettings(n int, v4gwAdd bool, v6gwAdd bool) (types.CustomizationIPSettings, bool, bool) {
	var v4gwFound, v6gwFound bool
	var obj types.CustomizationIPSettings

	ipv4Address := s.Config.NetworkInterfaces[n].Ipv4Address
	if ipv4Address != "" {
		ipv4mask := s.Config.NetworkInterfaces[n].Ipv4NetMask
		ipv4Gateway := s.Config.Ipv4Gateway
		obj.Ip = &types.CustomizationFixedIp{
			IpAddress: ipv4Address,
		}
		obj.SubnetMask = v4CIDRMaskToDotted(ipv4mask)
		// Check for the gateway
		if v4gwAdd && ipv4Gateway != "" && matchGateway(ipv4Address, ipv4mask, ipv4Gateway) {
			obj.Gateway = []string{ipv4Gateway}
			v4gwFound = true
		}
	} else {
		obj.Ip = &types.CustomizationDhcpIpGenerator{}
	}

	obj.DnsServerList = s.Config.NetworkInterfaces[n].DnsServerList
	obj.DnsDomain = s.Config.NetworkInterfaces[n].DnsDomain
	obj.IpV6Spec, v6gwFound = s.IPSettingsIPV6Address(n, v6gwAdd)

	return obj, v4gwFound, v6gwFound
}

func (s *StepCustomize) IPSettingsIPV6Address(n int, gwAdd bool) (*types.CustomizationIPSettingsIpV6AddressSpec, bool) {
	addr := s.Config.NetworkInterfaces[n].Ipv6Address
	var gwFound bool
	if addr == "" {
		return nil, gwFound
	}
	mask :=  s.Config.NetworkInterfaces[n].Ipv6NetMask
	gw := s.Config.Ipv6Gateway
	obj := &types.CustomizationIPSettingsIpV6AddressSpec{
		Ip: []types.BaseCustomizationIpV6Generator{
			&types.CustomizationFixedIpV6{
				IpAddress:  addr,
				SubnetMask: int32(mask),
			},
		},
	}
	if gwAdd && gw != "" && matchGateway(addr, mask, gw) {
		obj.Gateway = []string{gw}
		gwFound = true
	}
	return obj, gwFound
}

func v4CIDRMaskToDotted(mask int) string {
	m := net.CIDRMask(mask, 32)
	a := int(m[0])
	b := int(m[1])
	c := int(m[2])
	d := int(m[3])
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// matchGateway take an IP, mask, and gateway, and checks to see if the gateway
// is reachable from the IP address.
func matchGateway(a string, m int, g string) bool {
	ip := net.ParseIP(a)
	gw := net.ParseIP(g)
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(m, 32)
	} else {
		mask = net.CIDRMask(m, 128)
	}
	if ip.Mask(mask).Equal(gw.Mask(mask)) {
		return true
	}
	return false
}
