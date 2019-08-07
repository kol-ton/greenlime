export interface Renderable {
	isAlive: boolean;
	Render(renderContext: CanvasRenderingContext2D): Renderable[];
}
