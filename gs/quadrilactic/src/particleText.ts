import {Renderable} from "renderable";

export class ParticleText implements Renderable {
	private static degrees: number = Math.PI / 180;
	public isAlive: boolean;
	private xPosition: number;
	private yPosition: number;
	private text: string;
	private font: string;
	private fontSize: number;
	private rotation: number;
	private color: string;
	private opacity: number;

	public constructor(
		xPosition: number,
		yPosition: number,
		text: string,
		fontName: string,
		fontSize: number,
		rotation: number,
		color: string,
		opacity: number
	) {
		this.xPosition = xPosition;
		this.yPosition = yPosition;
		this.text = text;
		this.font = fontSize.toString() + "px " + fontName;
		this.fontSize = fontSize;
		this.rotation = rotation;
		this.color = color;
		this.opacity = opacity;
		this.isAlive = true;
	}

	public Render(renderContext: CanvasRenderingContext2D): Renderable[] {
		this.opacity -= 0.005;
		if (this.opacity <= 0) {
			this.isAlive = false;
		} else {
			renderContext.save();
			renderContext.globalAlpha = this.opacity;

			renderContext.translate(this.xPosition, this.yPosition);
			renderContext.rotate(this.rotation * ParticleText.degrees);
			renderContext.translate(-this.xPosition, -this.yPosition);

			renderContext.fillStyle = this.color;
			renderContext.font = this.font;
			renderContext.fillText(this.text.toString(), this.xPosition, this.yPosition + this.fontSize);

			renderContext.globalAlpha = 1;
			renderContext.restore();
		}

		return [] as Renderable[];
	}
}
