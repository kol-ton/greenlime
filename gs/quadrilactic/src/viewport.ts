import {Point} from "point";
import {Renderable} from "renderable";

export class Viewport {
	private renderContext: CanvasRenderingContext2D;
	private fixedRenderables: Renderable[];
	private backgroundRenderables: Renderable[];
	private foregroundRenderables: Renderable[];
	private initialBackgroundRenderables: Renderable[];
	private initialForegroundRenderables: Renderable[];
	private renderOffset: number;

	public get renderDimensions(): Point {
		return {
			x: this.renderContext.canvas.width,
			y: this.renderContext.canvas.height
		};
	}

	public get offset(): number {
		return this.renderOffset;
	}

	constructor(
		renderContext: CanvasRenderingContext2D,
		fixedRenderables: Renderable[],
		backgroundRenderables: Renderable[],
		foregroundRenderables: Renderable[]
	) {
		this.renderContext = renderContext;
		this.fixedRenderables = fixedRenderables;
		this.backgroundRenderables = backgroundRenderables;
		this.foregroundRenderables = foregroundRenderables;
		this.initialBackgroundRenderables = [].concat(backgroundRenderables);
		this.initialForegroundRenderables = [].concat(foregroundRenderables);
		this.renderOffset = 0;
	}

	public SlideUpTo(y: number): void {
		if (y > this.renderOffset) {
			this.renderOffset = y;
		}
	}

	public Render(fps?: number): void {
		this.renderContext.save();

		this.renderContext.translate(0, this.renderOffset);

		this.backgroundRenderables = this.RenderSubSet(this.backgroundRenderables);

		this.renderContext.restore();

		this.fixedRenderables = this.RenderSubSet(this.fixedRenderables);

		this.renderContext.save();

		this.renderContext.translate(0, this.renderOffset);

		this.foregroundRenderables = this.RenderSubSet(this.foregroundRenderables);

		this.renderContext.restore();

		if (fps) {
			this.renderContext.fillStyle = "#FFFFFF";
			this.renderContext.fillText("FPS: " + fps.toString(), 0, 10);
		}
	}

	public Reset(): void {
		this.renderOffset = 0;
		this.backgroundRenderables = [].concat(this.initialBackgroundRenderables);
		this.foregroundRenderables = [].concat(this.initialForegroundRenderables);
	}

	private RenderSubSet(subSet: Renderable[]): Renderable[] {
		let newRenderables: Renderable[] = subSet;
		for (let i: number = 0; i < subSet.length; i++) {
			newRenderables = subSet[i].Render(this.renderContext).concat(newRenderables);
		}

		return newRenderables.filter((renderable: Renderable) => {
			return renderable.isAlive;
		});
	}
}
