module github.com/free5gc/n3iwf/test

go 1.14

require (
	git.cs.nctu.edu.tw/calee/sctp v1.1.0
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/free5gc/aper v1.0.2
	github.com/free5gc/idgenerator v1.0.0
	github.com/free5gc/logger_conf v1.0.0
	github.com/free5gc/logger_util v1.0.0
	github.com/free5gc/ngap v1.0.4
	github.com/free5gc/path_util v1.0.0
	github.com/free5gc/version v1.0.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.5
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	github.com/wmnsk/go-gtp v0.7.4
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	golang.org/x/sys v0.0.0-20211213223007-03aa0b5f6827
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/free5gc/aper v1.0.2 => /home/k200/irene/free5gc/NFs/aper

//replace github.com/free5gc/ngap v1.0.4 => /home/k200/irene/free5gc/NFs/ngap
replace github.com/free5gc/ngap v1.0.4 => github.com/ireneLou/ngap v1.0.5-0.20211214030546-dbc96f154d94
