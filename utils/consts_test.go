package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConstsTestSuite struct {
	suite.Suite
}

func (suite *ConstsTestSuite) TestConsts() {

	// test datetime Zulu format
	suite.Equal("2006-01-02T15:04:05Z", ZULU_FORM)
}

func TestConstsTestSuite(t *testing.T) {
	suite.Run(t, new(ConstsTestSuite))
}
