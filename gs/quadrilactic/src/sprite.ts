import {Renderable} from "renderable";
import {Point} from "point";

export class Sprite implements Renderable {
	public isAlive: boolean = true;
	private image: HTMLImageElement;
	private internalDimensions: Point;

	constructor(imagePath: string, dimensions: Point) {
		this.image = new Image();
		this.image.addEventListener("load", () => { this.loaded(); }, false);
		this.image.src = imagePath;

		this.dimensions = dimensions;
	}

	public set dimensions(dimensions: Point) {
		this.internalDimensions = dimensions;
	}

	public Render(renderContext: CanvasRenderingContext2D): Renderable[] {
		renderContext.drawImage(
			this.image,
			// Source dimensions
			0,
			0,
			this.image.width,
			this.image.height,
			// Destination dimensions
			0,
			0,
			this.internalDimensions.x,
			this.internalDimensions.y);

		return [];
	}

	private loaded(): void {
		console.log("Loaded: " + this.image.src);
	}
}
