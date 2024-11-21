package godivert

type Layer uint8

const (
	LayerNetwork Layer = 0
	LayerForward Layer = 1
	LayerFlow    Layer = 2
	LayerSocket  Layer = 3
	LayerReflect Layer = 4
)
