export interface Point {
	x: number;
	y: number;
}

export interface MovingPoint extends Point {
	dX: number;
	dY: number;
}

export interface Rectangle extends Point {
	width: number;
	height: number;
}
