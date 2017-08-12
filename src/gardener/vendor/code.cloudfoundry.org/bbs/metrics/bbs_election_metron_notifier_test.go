package metrics_test

import (
	"os"
	"time"

	"code.cloudfoundry.org/bbs/metrics"
	mfakes "code.cloudfoundry.org/go-loggregator/testhelpers/fakes/v1"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/tedsuo/ifrit"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BBSElectionMetronNotifier", func() {
	var (
		reportInterval   time.Duration
		pmn              ifrit.Process
		fakeMetronClient *mfakes.FakeIngressClient
	)

	BeforeEach(func() {
		reportInterval = 100 * time.Millisecond
		fakeMetronClient = new(mfakes.FakeIngressClient)
	})

	JustBeforeEach(func() {
		pmn = ifrit.Invoke(metrics.NewBBSElectionMetronNotifier(lagertest.NewTestLogger("test"), fakeMetronClient))
	})

	AfterEach(func() {
		pmn.Signal(os.Interrupt)
		Eventually(pmn.Wait(), 2*time.Second).Should(Receive())
	})

	Context("when the metron notifier starts up", func() {
		It("should emit an event that BBS has started", func() {
			name, value := fakeMetronClient.SendMetricArgsForCall(0)
			Expect(name).To(Equal("BBSMasterElected"))
			Expect(value).To(Equal(1))
		})
	})
})
