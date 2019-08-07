import {Point} from "point";
import {Renderable} from "renderable";
import {Player} from "player";
import {Sprite} from "sprite";

export class Background implements Renderable {
	public isAlive: boolean = true;
	public showArrow: boolean = false;

	private renderPosition: Point;
	private renderDimensions: Point;
	private color: string;
	private offset: number = 0;
	private staticBackground: Sprite;
	private stars1: Sprite;
	private stars2: Sprite;
	private upArrow: Sprite;

	public constructor(
		renderPosition: Point,
		renderDimensions: Point,
		color: string,
		player: Player
	) {
		this.renderPosition = renderPosition;
		this.renderDimensions = renderDimensions;
		this.color = color;

		this.staticBackground = new Sprite("img/staticBackground.png", renderDimensions);
		this.stars1 = new Sprite("img/stars1.png", { x: renderDimensions.x, y: renderDimensions.y * 2 });
		this.stars2 = new Sprite("img/stars2.png", { x: renderDimensions.x, y: renderDimensions.y * 2 });
		this.upArrow = new Sprite("img/upArrow.png", { x: 120, y: 99 });
	}

	public SlideUpTo(y: number): void {
		if (y > this.offset) {
			this.offset = y;
		}
	}

	public Render(renderContext: CanvasRenderingContext2D): Renderable[] {

		let result: Renderable[] = [];

		result = result.concat(this.staticBackground.Render(renderContext));

		let lowerYPosition1: number = this.offset % (this.renderDimensions.y * 2);
		let upperYPosition1: number = lowerYPosition1 - (this.renderDimensions.y * 2);

		renderContext.save();
		renderContext.translate(0, lowerYPosition1);
		result = result.concat(this.stars1.Render(renderContext));
		renderContext.restore();

		renderContext.save();
		renderContext.translate(0, upperYPosition1);
		result = result.concat(this.stars1.Render(renderContext));
		renderContext.restore();

		let lowerYPosition2: number = (this.offset / 2) % (this.renderDimensions.y * 2);
		let upperYPosition2: number = lowerYPosition2 - (this.renderDimensions.y * 2);

		renderContext.save();
		renderContext.translate(0, lowerYPosition2);
		result = result.concat(this.stars2.Render(renderContext));
		renderContext.restore();

		renderContext.save();
		renderContext.translate(0, upperYPosition2);
		result = result.concat(this.stars2.Render(renderContext));
		renderContext.restore();

		if (this.showArrow && this.offset < (this.renderDimensions.y * 2)) {
			renderContext.save();

			renderContext.globalAlpha = 0.5;
			renderContext.translate(300, this.offset + 40);
			this.upArrow.Render(renderContext);

			renderContext.restore();
		}

		return result;
	}

	public Reset(): void {
		this.showArrow = true;
		this.offset = 0;
	}
}
